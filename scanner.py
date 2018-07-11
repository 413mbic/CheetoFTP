import codecs
import time
import queue
import os
import sys
import urllib.request
from threading import Thread, Lock
from urllib.parse import urljoin

import ftputil

FTP_SCHEME_PREFIX = 'ftp://'


class Scanner:
    def __init__(self, url, user='anonymous', passwd='anonymous',
                 max_threads=2, max_itemsize=209715200):
        self.url = url
        self.archive_dir = os.path.join(self.url, 'archive')
        self.item_dir = os.path.join(self.url, 'item')
        self.worker_timeout = 5
        self.symlinks = set()
        self.symlink_destinations = set()
        self.found_dirs = set()
        self.archive_path = os.path.join(self.archive_dir, self.url)
        self.item_number_path = os.path.join(self.archive_dir, self.url \
                                             + '_item_number')
        self.symlink_path = os.path.join(self.item_dir, self.url + '_symlinks')
        self.bad_url_path = os.path.join(self.item_dir, self.url + '_bad_url')

        self._problem_paths = {}
        self._item_cache = []
        self._ftp_user = user
        self._ftp_pass = passwd
        self._max_threads = max_threads
        self._work_queue = queue.Queue()
        self._archive_queue = queue.Queue()
        self._file_queue = [queue.Queue() for i in range(0, max_threads)]
        self._itemsize = [0 for i in range(0, max_threads)]
        self._archivesize = 0
        self._max_itemsize = max_itemsize
        self._start_dir = None
        self._item_number = 0
        
        if not os.path.isdir(self.archive_dir):
           os.makedirs(self.archive_dir)
        if not os.path.isdir(self.item_dir):
           os.makedirs(self.item_dir)

        self._symlink_cnx = codecs.open(self.symlink_path, 'w', encoding='utf8')
        self._archive_cnx = codecs.open(self.archive_path, 'w', encoding='utf8')

    def _item_save_checkpoint(self, wid):
        self._itemsize[wid] = 0

        # _item_number is shared between threads,
        # so we need to use a primitive lock before
        # incrementing it.

        lock = Lock()
        lock.acquire()
        try:
            self._item_number += 1
        finally:
            lock.release()

        item_name = '{}_{}'.format(self.url, self._item_number)
        item_path = os.path.join(self.item_dir, item_name)

        num_files = 0
        itemsize = 0

        with codecs.open(item_path, 'w', encoding='utf8') as f:
            while not self._file_queue[wid].empty():
                file_size, file_path = self._file_queue[wid].get()
                num_files += 1
                itemsize += file_size
                f.write('{}\n'.format(file_path))
                self._file_queue[wid].task_done()

            f.write('ITEM_NAME: {}\n'.format(item_name))
            f.write('ITEM_TOTAL_SIZE: {}\n'.format(itemsize))
            f.write('ITEM_TOTAL_LINKS: {}\n'.format(num_files))

    def _save_new_url(self, status, full_path, wid, size=0):
        path_tuple = (size, full_path)

        if 'D' in status:
            if full_path in self.found_dirs:
                return None
            self.found_dirs.add(full_path)

        self._itemsize[wid] += size
        self._file_queue[wid].put(path_tuple)
        if 'D' in status:
            for s in ['/', '/.', '/..']:
                self._file_queue[wid].put((size, full_path + s))

        if self._itemsize[wid] > self._max_itemsize:
            self._item_save_checkpoint(wid)

        self._archivesize += 1
        self._archive_queue.put(path_tuple)
        if 'D' in status:
            self._archivesize += 3
            for s in ['/', '/.', '/..']:
                self._archive_queue.put((size, full_path + s))

        if self._archivesize >= 1000:
            self._save_to_archive()

        #print('{}, {}'.format(self._file_queue[wid].qsize(), self._itemsize))
        #print('>> [{}-{}], {}'.format(status, wid, full_path))

    def _save_to_archive(self):
        self._archivesize = 0

        received = []

        lock = Lock()
        lock.acquire()
        try:
            while not self._archive_queue.empty():
                file_size, file_path = self._archive_queue.get()
                received.append('{}, {}'.format(file_size, file_path))
                self._archive_queue.task_done()
            self._archive_cnx.write('\n'.join(received) + '\n')
            self._archive_cnx.flush()
        finally:
            lock.release()

    def _save_symlink(self, symlink, destination, cnx, wid):
        if symlink == destination:
            return None

        splitted = destination.split('/')[3:-1]

        while len(splitted) > 0:
            path = '/' + '/'.join(splitted)
            full_path = self.get_full_path(path)

            if not full_path in self.found_dirs:
                status = 'D'
                if cnx.path.islink(path):
                    status = 'LD'

                self._work_queue.put(path)
                self._save_new_url(status, full_path, wid)

                if status == 'LD':
                    destination = cnx.lstat(path)._st_target
                    destination = cnx.path.abspath(destination)
                    destination = self.get_full_path(destination.rstrip('../'))
                    self._save_symlink(full_path, destination, cnx, wid)

            splitted = splitted[:-1]

        if not any(map(lambda s: symlink.startswith(s), self.symlinks)):
            self.symlinks.add(symlink)
            self.symlink_destinations.add(destination)
            self._symlink_cnx.write('{} -> {}\n'.format(symlink, destination))
            self._symlink_cnx.flush()

    def _check_bad_data(self):
        try:
            urllib.request.urlopen('/'.join([self.FTP_SCHEME_PREFIX+self.url,
                'NONEXISTINGFILEdgdjahxnedadbacxjbc']))
        except Exception as e:
            with codecs.open(self.bad_url_path, 'w', encoding='utf8') as f:
                if r"\'" in str(e):
                    f.write(str(e).split('"', 1)[1].rsplit('"', 1)[0]
                            .replace(r"\'", "'"))
                else:
                    f.write(str(e).split("'", 1)[1].rsplit("'", 1)[0])

    def _scan_dir(self, dir, wid, cnx):
        if any(map(lambda s: self.get_full_path(dir).startswith(s),
                   self.symlink_destinations)):
            return None

        print('Checking {}.'.format(dir.encode('latin1').decode('utf8')))
        sys.stdout.flush()

        # if we don't change dirs here,
        # isdir/isfile will return false-positives
        cnx.chdir(dir)
        #print('CURRENT DIRECTORY {}'.format(cnx.getcwd()))
        names = cnx.listdir('.')

        for name in names:
            path = cnx.path.abspath(name)
            full_path = self.get_full_path(path)

            if cnx.path.isfile(name):
                status = 'F'

                size = cnx.path.getsize(path)

                self._save_new_url(status, full_path, wid, size)
            elif cnx.path.islink(name) and cnx.path.isdir(name):
                status = 'LD'

                destination = cnx.lstat(name)._st_target
                destination = cnx.path.abspath(destination)
                destination = self.get_full_path(destination.rstrip('../'))

                self._work_queue.put(path)
                self._save_new_url(status, full_path, wid)
                self._save_symlink(full_path, destination, cnx, wid)
            elif cnx.path.islink(name):
                status = 'L'

                destination = cnx.lstat(name)._st_target
                destination = cnx.path.abspath(destination)
                destination = self.get_full_path(destination.rstrip('../'))

                self._save_new_url(status, full_path, wid)
                self._save_symlink(full_path, destination, cnx, wid)
            elif cnx.path.isdir(name):
                status = 'D'

                self._work_queue.put(path)
                self._save_new_url(status, full_path, wid)
            else:
                status = 'X'

    def _scan_dir_worker(self, wid):
        cnx = self.new_worker()

        queue_empty_count = 0

        while True:
            # Snuff all the errors so that workers don't die
            # along the way. Also re-establish connection
            # incase that dies too.
            try:
                path = self._work_queue.get()
                self._scan_dir(path, wid, cnx)
                self._work_queue.task_done()
            except Exception as e:
                print('WORKER {} ERROR - Re-establishing connection...'
                      .format(wid))
                print(e)

                if not path in self._problem_paths:
                    self._problem_paths[path] = 0
                self._problem_paths[path] += 1
                if self._problem_paths[path] <= 5:
                    print('Requeueing {}.'.format(path))
                    self._work_queue.put(path)
                else:
                    print('Skipping {}.'.format(path))
                self._work_queue.task_done()

                cnx = self.new_worker()

        print('STOP', wid)

    def new_worker(self):
        return ftputil.FTPHost(self.url, self._ftp_user, self._ftp_pass)

    def get_full_path(self, path):
        rel_path = os.path.relpath(path, start=self._start_dir)
        rel_path = rel_path.replace(r'\','/')
        rel_path = rel_path.encode('latin1').decode('utf8')

        return urljoin(''.join([self.FTP_SCHEME_PREFIX, self.url]), rel_path)

    def scan(self):
        cnx = self.new_worker()

        self._start_dir = '/'
        current_dir = cnx.path.abspath(cnx.getcwd())
        print(self._start_dir)
        print('STARTING IN DIR: {}'.format(self._start_dir))

        start_dir_status = 'D'
        if cnx.path.islink(self._start_dir):
            start_dir_status = 'LD'
        self._save_new_url(start_dir_status,
                           self.get_full_path(self._start_dir), -1)
        self._scan_dir(self._start_dir, 0, cnx)

        if not current_dir == self._start_dir:
            current_dir_status = 'D'
            if cnx.path.islink(current_dir):
                current_dir_status = 'LD'
            self._save_new_url(current_dir_status,
                               self.get_full_path(current_dir), -1)
            self._scan_dir(current_dir, -1, cnx)

        self._archive = Thread(target=self._save_to_archive)
        self._archive.daemon = True
        self._archive.start()

        for wid in range(self._max_threads):
            t = Thread(target=self._scan_dir_worker, args=(wid,))
            t.daemon = True
            t.start()

        self._work_queue.join()

        #print('Discovery complete, saving remaining files to items...')
        for wid in range(self._max_threads):
            self._item_save_checkpoint(wid)
            self._file_queue[wid].join()

        self._save_to_archive()
        self._archive_queue.join()

        print('Testing for non-existing URL response...')
        self._check_bad_data()

        print('Writing max item number...')
        with open(self.item_number_path, 'w') as f:
            f.write(str(self._item_number))

        print('All done :D')
