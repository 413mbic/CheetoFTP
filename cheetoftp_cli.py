import argparse, scanner

parser = argparse.ArgumentParser(description='CheetoFTP - A cheese flavoured FTP file discovery script.')

parser.add_argument('url', metavar='URL', help='URL to scan')

parser.add_argument('--user', metavar='User', help="Username to use to login into the FTP URL. Defaults to `anonymous`.", default="anonymous")
parser.add_argument('--passwd', metavar='Passwd', help="Password to use to login into the FTP URL. Defaults to `anonymous`.", default="anonymous")
parser.add_argument('--threads', metavar='Threads', type=int, help="The number of concurrent connections to make to the FTP server while scanning. Defaults to 2.", default=2)
parser.add_argument('--max-itemsize', metavar='Max Itemsize', type=int, help="The number of bytes each item should aspire to be. Defaults to 209715200.", default=209715200)

args = parser.parse_args()

s = scanner.Scanner(args.url,
                    user=args.user,
                    passwd=args.passwd,
                    max_threads=args.threads,
                    max_itemsize=args.max_itemsize )
s.scan()