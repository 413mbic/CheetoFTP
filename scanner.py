import ftputil, time, queue, os
from threading import Thread, Lock
from urllib.parse import urljoin

class Scanner:
    def __init__(self, url, user="anonymous", passwd="anonymous",
                 max_threads=2, max_itemsize=209715200):
        self.url = url
        self.__item_cache = []
        self.__ftp_user = user
        self.__ftp_pass = passwd
        self.__max_threads = max_threads
        self.__work_queue = queue.Queue()
        self.__file_queue = [queue.Queue() for i in range(0, max_threads)]
        self.__itemsize = [0 for i in range(0, max_threads)]
        self.__max_itemsize = max_itemsize
        self.__item_number = 0
        self.__start_dir = None

    def __item_save_checkpoint(self, wid):

        if self.__itemsize[wid] > self.__max_itemsize:
            self.__itemsize[wid] = 0

            # __item_number is shared between threads,
            # so we need to use a primitive lock before
            # incrementing it.

            lock = Lock()
            lock.acquire()

            try:
                self.__item_number += 1
            finally:
                lock.release()

            if os.path.isdir("item") is False:
                os.mkdir("item")
            
            item_name = "{}_{}".format(self.url, self.__item_number)
            item_path = os.path.join("item", item_name)

            num_files = 0
            itemsize = 0

            with open(item_path, 'w') as f:
                while self.__file_queue[wid].empty() is False:
                    file_size, file_path = self.__file_queue[wid].get()
                    num_files += 1
                    itemsize += file_size
                    f.write("{}\n".format(file_path))

                f.write("ITEM_NAME: {}\n".format(item_name))
                f.write("ITEM_TOTAL_SIZE: {}\n".format(itemsize))
                f.write("ITEM_TOTAL_LINKS: {}\n".format(num_files))

    def __save_to_archive(self, file_size, file_path):
        if os.path.isdir("archive") is False:
                os.mkdir("archive")

        archive_path = "archive/{}".format(self.url)

        if os.path.isfile(archive_path):
            archive_cnx = open(archive_path, 'a')
        else:
            archive_cnx = open(archive_path, 'w')

        archive_cnx.write("{}, {}\n".format(file_size, file_path))
        
        archive_cnx.close()

    def __scan_dir(self, dir, wid, cnx):

        # if we don't change dirs here,
        # isdir/isfile will return false-positives
        cnx.chdir(dir)

        #print("CURRENT DIRECTORY {}".format(cnx.getcwd()))
        names = cnx.listdir(".")
        
        for name in names:
            
            path = cnx.path.join(dir,name)

            if cnx.path.isfile(path):
                status = "F"

                size = cnx.path.getsize(path)

                rel_path = os.path.relpath(path, start=self.__start_dir)
                rel_path = rel_path.replace("\\","/")
                full_path = urljoin("ftp://{}".format(self.url), rel_path)

                path_tuple = (size, full_path)

                self.__itemsize[wid] += size

                self.__file_queue[wid].put(path_tuple)

                self.__item_save_checkpoint(wid)

                t = Thread(target=self.__save_to_archive, args=(size,full_path))
                t.start()

                print("{}, {}".format(self.__file_queue[wid].qsize(), self.__itemsize))

            elif cnx.path.isdir(path):
                self.__work_queue.put(path)
                status = "D"
                
            elif cnx.path.islink(path):
                status = "L"

            else:
                status = "X"
            
            if status == "F":
                print(">> [{}-{}], {}".format(status, wid, full_path))
        

    def __scan_dir_worker(self, wid):

        cnx = ftputil.FTPHost(self.url,
                              self.__ftp_user,
                              self.__ftp_pass)

        while True:
            # Snuff all the errors so that workers don't die
            # along the way. Also re-establish connection
            # incase that dies too.
            try:
                path = self.__work_queue.get()
                self.__scan_dir(path, wid, cnx)
            except Exception as e:
                print("WORKER {} ERROR - Re-establishing connection...".format(wid))
                print(e)
                cnx = ftputil.FTPHost(self.url,
                              self.__ftp_user,
                              self.__ftp_pass)

    def scan(self):      
        
        cnx = ftputil.FTPHost(self.url,
                              self.__ftp_user,
                              self.__ftp_pass) 

        self.__start_dir = cnx.path.abspath(cnx.getcwd())
        print("STARTING IN DIR: {}".format(self.__start_dir))
        self.__scan_dir(self.__start_dir,-1, cnx)


        for wid in range(self.__max_threads):
            t = Thread(target=self.__scan_dir_worker, args=(wid,))
            t.daemon = True
            t.start()
        
        self.__work_queue.join()
        print("All done :D")