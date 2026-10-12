"""CLI: python3 -m ramhash FILE... | python3 -m ramhash -s "text" """

import sys

from . import digest, digest_file

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        sys.exit('usage: python3 -m ramhash FILE... | -s "text"')
    if args[0] == "-s":
        print(digest(" ".join(args[1:])))
    else:
        for path in args:
            print("%s  %s" % (digest_file(path), path))
