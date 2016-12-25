from threading import Thread, Lock
from urllib.parse import urljoin

import codecs
import ftputil
import time
import queue
import os
import urllib.request


class Scanner:
    ARCHIVE_DIR = "archive"
    ITEM_DIR = "item"
    FTP_SCHEME_PREFIX = "ftp://"

    def __init__(self, url, user="anonymous", passwd="anonymous",
          max_threads=2, max_itemsize=209715200):
        self.url = url
        self.worker_timeout = 5
        self.archive_path = os.path.join(self.ARCHIVE_DIR, self.url)
        self.symlink_path = os.path.join(self.ITEM_DIR,
            "_".join([self.url, "symlinks"]))
        self.bad_url_path = os.path.join(self.ITEM_DIR,
            "_".join([self.url, "bad_url"]))

        self.__item_cache = []
        self.__ftp_user = user
        self.__ftp_pass = passwd
        self.__max_threads = max_threads
        self.__work_queue = queue.Queue()
        self.__archive_queue = queue.Queue()
        self.__symlink_queue = queue.Queue()
        self.__file_queue = [queue.Queue() for i in range(0, max_threads)]
        self.__itemsize = [0 for i in range(0, max_threads)]
        self.__max_itemsize = max_itemsize
        self.__start_dir = None
        self.__item_number = 0
        
        if not os.path.isdir(self.ARCHIVE_DIR):
           os.mkdir(self.ARCHIVE_DIR)
        if not os.path.isdir(self.ITEM_DIR):
           os.mkdir(self.ITEM_DIR)

    def __item_save_checkpoint(self, wid):
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

        item_name = "{}_{}".format(self.url, self.__item_number)
        item_path = os.path.join(self.ITEM_DIR, item_name)

        num_files = 0
        itemsize = 0

        with codecs.open(item_path, "w", encoding="utf8") as f:
            while not self.__file_queue[wid].empty():
                file_size, file_path = self.__file_queue[wid].get()
                num_files += 1
                itemsize += file_size
                f.write("{}\n".format(file_path))
                self.__file_queue[wid].task_done()

            f.write("ITEM_NAME: {}\n".format(item_name))
            f.write("ITEM_TOTAL_SIZE: {}\n".format(itemsize))
            f.write("ITEM_TOTAL_LINKS: {}\n".format(num_files))

    def __save_new_url(self, status, full_path, wid, size=0):
        path_tuple = (size, full_path)

        self.__itemsize[wid] += size
        self.__file_queue[wid].put(path_tuple)

        if self.__itemsize[wid] > self.__max_itemsize:
            self.__item_save_checkpoint(wid)

        self.__archive_queue.put((size, full_path))

        print("{}, {}".format(self.__file_queue[wid].qsize(), self.__itemsize))
        print(">> [{}-{}], {}".format(status, wid, full_path))

    def __save_to_archive(self):
        archive_cnx = codecs.open(self.archive_path,
            "a" if os.path.isfile(self.archive_path) else "w",
            encoding="utf8")

        while not (self.__work_queue.empty() or self.__archive_queue.empty()):
            file_size, file_path = self.__archive_queue.get()
            archive_cnx.write("{}, {}\n".format(file_size, file_path))
            self.__archive_queue.task_done()

    def __save_symlink(self):
        archive_cnx = codecs.open(self.symlink_path,
            "a" if os.path.isfile(self.symlink_path) else "w",
            encoding="utf8")
        processed_symlinks = []

        while not self.__work_queue.empty() and not self.__archive_queue.empty():
            symlink, destination = self.__symlink_queue.get()

            if not any(map(lambda l: symlink.startswith(l), processed_symlinks)):
                processes_symlinks.append(symlink)
                self.__symlink_cnx.write("{}, {}\n".format(symlink, destination))

            self.__symlink_queue.task_done()

    def __check_bad_data(self):
        try:
            urllib.request.urlopen('/'.join([self.FTP_SCHEME_PREFIX+self.url,
                "NONEXISTINGFILEdgdjahxnedadbacxjbc"]))
        except Exception as e:
            with codecs.open(self.bad_url_path, 'w', encoding='utf8') as f:
                if r"\'" in str(e):
                    f.write(str(e).split('"', 1)[1].rsplit('"', 1)[0].replace(r"\'", "'"))
                else:
                    f.write(str(e).split("'", 1)[1].rsplit("'", 1)[0])

    def __scan_dir(self, dir, wid, cnx):
        # if we don't change dirs here,
        # isdir/isfile will return false-positives
        cnx.chdir(dir)

        #print("CURRENT DIRECTORY {}".format(cnx.getcwd()))
        names = cnx.listdir(".")

        for name in names:
            path = cnx.path.join(dir, name)

            if cnx.path.isfile(path):
                status = "F"

                size = cnx.path.getsize(path)
                full_path = self.get_full_path(path)

                self.__save_new_url(status, full_path, wid, size)
            elif cnx.path.islink(path) and cnx.path.isdir(path):
                status = "LD"

                #we need the destination of the symlink here
                #destination = 

                full_path = self.get_full_path(path)
                self.__work_queue.put(path)
                self.__save_new_url(status, full_path, wid)
                self.__symlinks.put((full_path, destination))
            elif cnx.path.islink(path):
                status = "L"

                #we need the destination of the symlink here
                #destination = 

                full_path = self.get_full_path(path)
                self.__save_new_url(status, full_path, wid)
                self.__symlinks.put((full_path, destination))
            elif cnx.path.isdir(path):
                status = "D"

                full_path = self.get_full_path(path)
                self.__work_queue.put(path)
                self.__save_new_url(status, full_path, wid)
            else:
                status = "X"

    def __scan_dir_worker(self, wid):
        cnx = ftputil.FTPHost(self.url,
            self.__ftp_user,
            self.__ftp_pass)

        queue_empty_count = 0

        while True:
            # Snuff all the errors so that workers don't die
            # along the way. Also re-establish connection
            # incase that dies too.
            try:
                path = self.__work_queue.get()
                self.__scan_dir(path, wid, cnx)
                self.__work_queue.task_done()
            except Exception as e:
                print("WORKER {} ERROR - Re-establishing connection...".format(wid))
                print(e)
                cnx = self.new_worker()

    def new_worker(self):
        return ftputil.FTPHost(self.url, self.__ftp_user, self.__ftp_pass)

    def get_full_path(self, path):
        rel_path = os.path.relpath(path, start=self.__start_dir)
        rel_path = rel_path.replace("\\","/")
        rel_path = rel_path.encode("latin1").decode("utf8")

        return urljoin("".join([self.FTP_SCHEME_PREFIX, self.url]), rel_path)

    def scan(self):
        cnx = self.new_worker()

        self.__start_dir = cnx.path.abspath(cnx.getcwd())
        print("STARTING IN DIR: {}".format(self.__start_dir))
        self.__save_new_url("D", self.get_full_path("/"), -1)
        self.__scan_dir(self.__start_dir, -1, cnx)

        self.__archive = Thread(target=self.__save_to_archive)
        self.__archive.daemon = True
        self.__archive.start()

        self.__symlinks = Thread(target=self.__save_symlink)
        self.__symlinks.daemon = True
        self.__symlinks.start()

        for wid in range(self.__max_threads):
            t = Thread(target=self.__scan_dir_worker, args=(wid,))
            t.daemon = True
            t.start()

        self.__work_queue.join()

        print("Discovery complete, saving remaining files to items...")
        for wid in range(self.__max_threads):
            self.__item_save_checkpoint(wid)

        print("Testing for non-existing URL response...")
        self.__check_bad_data()

        print("All done :D")
