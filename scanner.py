from threading import Thread, Lock
from urllib.parse import urljoin

import codecs
import ftputil
import time
import queue
import os
import urllib.request


class Scanner:
    FTP_SCHEME_PREFIX = "ftp://"

    def __init__(self, url, user="anonymous", passwd="anonymous",
          max_threads=2, max_itemsize=209715200):
        self.url = url
        self.archive_dir = os.path.join(self.url, "archive")
        self.item_dir = os.path.join(self.url, "item")
        self.worker_timeout = 5
        self.symlinks = set()
        self.symlink_destinations = set()
        self.found_dirs = set()
        self.archive_path = os.path.join(self.archive_dir, self.url)
        self.item_number_path = os.path.join(self.archive_dir, self.url \
            + "_item_number")
        self.symlink_path = os.path.join(self.item_dir,
            "_".join([self.url, "symlinks"]))
        self.bad_url_path = os.path.join(self.item_dir,
            "_".join([self.url, "bad_url"]))

        self.__problem_paths = {}
        self.__item_cache = []
        self.__ftp_user = user
        self.__ftp_pass = passwd
        self.__max_threads = max_threads
        self.__work_queue = queue.Queue()
        self.__archive_queue = queue.Queue()
        self.__file_queue = [queue.Queue() for i in range(0, max_threads)]
        self.__itemsize = [0 for i in range(0, max_threads)]
        self.__archivesize = 0
        self.__max_itemsize = max_itemsize
        self.__start_dir = None
        self.__item_number = 0
        
        if not os.path.isdir(self.archive_dir):
           os.makedirs(self.archive_dir)
        if not os.path.isdir(self.item_dir):
           os.makedirs(self.item_dir)

        self.__symlink_cnx = codecs.open(self.symlink_path, "w", encoding="utf8")
        self.__archive_cnx = codecs.open(self.archive_path, "w", encoding="utf8")

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
        item_path = os.path.join(self.item_dir, item_name)

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

        if "D" in status:
            if full_path in self.found_dirs:
                return None
            self.found_dirs.add(full_path)

        self.__itemsize[wid] += size
        self.__file_queue[wid].put(path_tuple)
        if "D" in status:
            for s in ["/", "/.", "/.."]:
                self.__file_queue[wid].put((size, full_path + s))

        if self.__itemsize[wid] > self.__max_itemsize:
            self.__item_save_checkpoint(wid)

        self.__archivesize += 1
        self.__archive_queue.put(path_tuple)
        if "D" in status:
            self.__archivesize += 3
            for s in ["/", "/.", "/.."]:
                self.__archive_queue.put((size, full_path + s))

        if self.__archivesize >= 1000:
            self.__save_to_archive()

        #print("{}, {}".format(self.__file_queue[wid].qsize(), self.__itemsize))
        #print(">> [{}-{}], {}".format(status, wid, full_path))

    def __save_to_archive(self):
        self.__archivesize = 0

        received = []

        lock = Lock()
        lock.acquire()
        try:
            while not self.__archive_queue.empty():
                file_size, file_path = self.__archive_queue.get()
                received.append("{}, {}".format(file_size, file_path))
                self.__archive_queue.task_done()
            self.__archive_cnx.write("\n".join(received) + "\n")
            self.__archive_cnx.flush()
        finally:
            lock.release()

    def __save_symlink(self, symlink, destination, cnx, wid):
        if symlink == destination:
            return None

        splitted = destination.split('/')[3:-1]

        while len(splitted) > 0:
            path = "/" + "/".join(splitted)
            full_path = self.get_full_path(path)

            if not full_path in self.found_dirs:
                status = "D"
                if cnx.path.islink(path):
                    status = "LD"

                self.__work_queue.put(path)
                self.__save_new_url(status, full_path, wid)

                if status == "LD":
                    destination = cnx.lstat(path)._st_target
                    destination = cnx.path.abspath(destination)
                    destination = self.get_full_path(destination.rstrip('../'))
                    self.__save_symlink(full_path, destination, cnx, wid)

            splitted = splitted[:-1]

        if not any(map(lambda s: symlink.startswith(s), self.symlinks)):
            self.symlinks.add(symlink)
            self.symlink_destinations.add(destination)
            self.__symlink_cnx.write("{} -> {}\n".format(symlink, destination))
            self.__symlink_cnx.flush()

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
        if any(map(lambda s: self.get_full_path(dir).startswith(s), self.symlink_destinations)):
            return None

        print('Checking {}.'.format(dir))

        # if we don't change dirs here,
        # isdir/isfile will return false-positives
        cnx.chdir(dir)
        #print("CURRENT DIRECTORY {}".format(cnx.getcwd()))
        names = cnx.listdir(".")

        for name in names:
            path = cnx.path.abspath(name)
            full_path = self.get_full_path(path)

            if cnx.path.isfile(name):
                status = "F"

                size = cnx.path.getsize(path)

                self.__save_new_url(status, full_path, wid, size)
            elif cnx.path.islink(name) and cnx.path.isdir(name):
                status = "LD"

                destination = cnx.lstat(name)._st_target
                destination = cnx.path.abspath(destination)
                destination = self.get_full_path(destination.rstrip('../'))

                self.__work_queue.put(path)
                self.__save_new_url(status, full_path, wid)
                self.__save_symlink(full_path, destination, cnx, wid)
            elif cnx.path.islink(name):
                status = "L"

                destination = cnx.lstat(name)._st_target
                destination = cnx.path.abspath(destination)
                destination = self.get_full_path(destination.rstrip('../'))

                self.__save_new_url(status, full_path, wid)
                self.__save_symlink(full_path, destination, cnx, wid)
            elif cnx.path.isdir(name):
                status = "D"

                self.__work_queue.put(path)
                self.__save_new_url(status, full_path, wid)
            else:
                status = "X"

    def __scan_dir_worker(self, wid):
        cnx = self.new_worker()

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

                if not path in self.__problem_paths:
                    self.__problem_paths[path] = 0
                self.__problem_paths[path] += 1
                if self.__problem_paths[path] <= 5:
                    print('Retrying {}.'.format(path))
                    self.__work_queue.put(path)
                else:
                    print('Skipping {}.'.format(path))
                self.__work_queue.task_done()

                cnx = self.new_worker()

        print('STOP', wid)

    def new_worker(self):
        return ftputil.FTPHost(self.url, self.__ftp_user, self.__ftp_pass)

    def get_full_path(self, path):
        rel_path = os.path.relpath(path, start=self.__start_dir)
        rel_path = rel_path.replace("\\","/")
        rel_path = rel_path.encode("latin1").decode("utf8")

        return urljoin("".join([self.FTP_SCHEME_PREFIX, self.url]), rel_path)

    def scan(self):
        cnx = self.new_worker()

        self.__start_dir = "/"
        current_dir = cnx.path.abspath(cnx.getcwd())
        print(self.__start_dir)
        print("STARTING IN DIR: {}".format(self.__start_dir))

        start_dir_status = "D"
        if cnx.path.islink(self.__start_dir):
            start_dir_status = "LD"
        self.__save_new_url(start_dir_status, self.get_full_path(self.__start_dir), -1)
        self.__scan_dir(self.__start_dir, 0, cnx)

        if not current_dir == self.__start_dir:
            current_dir_status = "D"
            if cnx.path.islink(current_dir):
                current_dir_status = "LD"
            self.__save_new_url(current_dir_status, self.get_full_path(current_dir), -1)
            self.__scan_dir(current_dir, -1, cnx)

        self.__archive = Thread(target=self.__save_to_archive)
        self.__archive.daemon = True
        self.__archive.start()

        for wid in range(self.__max_threads):
            t = Thread(target=self.__scan_dir_worker, args=(wid,))
            t.daemon = True
            t.start()

        self.__work_queue.join()

        #print("Discovery complete, saving remaining files to items...")
        for wid in range(self.__max_threads):
            self.__item_save_checkpoint(wid)
            self.__file_queue[wid].join()

        self.__save_to_archive()
        self.__archive_queue.join()

        print("Testing for non-existing URL response...")
        self.__check_bad_data()

        print("Writing max item number...")
        with open(self.item_number_path, 'w') as f:
            f.write(str(self.__item_number))

        print("All done :D")
