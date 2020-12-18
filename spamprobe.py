#!/usr/bin/env python3
# Copyright (C) 2020 Ian Haywood
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""
spamprobe.py - a Python Bayesian spam filter

requires Python 3.6+ 
can be úsed as a module, refer to functions 'learn' and 'probe'.
Both take a pair of dict-like objects (words_db and msg_db) which must be 
persisted by the caller. 

can also be used on the command line, run with "-h" to see options. 
"""


import traceback
import shelve
import email
from email.policy import default
import sys
import os.path, os
import datetime
import re
import argparse
from html.parser import HTMLParser


class _MyHTMLParser(HTMLParser):

    def __init__(self):
        HTMLParser.__init__(self)
        self.words = []
        self.ignore = 0
        
    def handle_starttag(self, tag, attrs):
        if tag in ["script", "template"]:
            self.ignore += 1
        if tag == "img":
            for n, v in attrs:
                if n == "alt":
                    self.words.extend(_text_parse(v))

    def handle_endtag(self, tag):
        if tag in ["script", "template"]: # "style"
            self.ignore -= 1

    def handle_data(self, data):
        if self.ignore == 0:
            self.words.extend(_text_parse(data))
            
def _html_parse(html):
    parser = _MyHTMLParser()
    parser.feed(html)
    parser.close()
    return parser.words

def _today():
    return datetime.date.today().toordinal()
  
def _text_parse(text):
    return [i for i in re.split(r"\W+", text) if len(i) > 3]  
    
def _process_mail(mail, logging=True):
    html = plain = None 
    for part in mail.walk():
        if part.get_content_type() == "text/html":
            html = part.get_content()
            if type(html) is bytes:
                c = part.get_charset() or "us-ascii"
                html = str(html, c, "ignore")
        elif part.get_content_type() == "text/plain":
            plain = part.get_content()
            if type(plain) is bytes:
                c = part.get_charset() or "us-ascii"
                plain = str(plain, c, "ignore")
    if html is None and plain is None:
        if logging:
            print("no body found")
        return []
    elif html and plain is None:
        words = _html_parse(html)
    else:
        words = _text_parse(plain)
    for k, v in mail.items():
        if k in ("Subject", "From", "Reply-To"):
            words.extend(_text_parse(str(v)))
        if k.startswith("X-"):
            words.extend(_text_parse(str(v)))
            words.append(str(k))
    try:
        h = mail["Date"].datetime.astimezone().hour
        if h < 8:
            t = "Date*overnight"
        elif h >= 8 and h < 17:   
            t = "Date*business"
        else:
            t = "Date*evening" 
        words.append(t)
    except:
        if logging:
            traceback.print_exc()
            
    return words
 

def learn(words_db, msg_db, mail, spam, logging=True):
    """
    learn zbout a message
    
     words_db: dict holding learnt words
     msg_db: dict holding seen meesages, keyed by Message-ID
     mail: the message, parsed to a email.message.EmailMessage
     (i.e. the "new" 3.6+ email class)
     spam: True if spam False if ham
     logging: log to stdout
    """
    msg_id = mail.get("Message-ID")
    if msg_id is None:
        msg_id = "%s/%s" % (mail["Date"], mail["From"])
    previous = (msg_id in msg_db)
    msg_db[msg_id] = spam
    if previous:
        prev_spam = msg_db[msg_id]
        if prev_spam == spam:
            if logging:
                print("old message, not reclassified")
            return
        elif logging:
            print("old message, reclassified")
    elif logging:
        print("new message")    
    for w in _process_mail(mail):
        if w in words_db:    
            _, spam_no, ham_no = words_db[w]
            if previous:
                if prev_spam:
                    spam_no = max(0, spam_no-1)
                else:
                    ham_no = max(0, ham_no-1)
        else:
            ham_no = 0
            spam_no = 0
        if spam:
            spam_no += 1
        else:
            ham_no += 1
        words_db[w] = (today(), spam_no, ham_no)
        
def probe(words_db, msg_db, mail, max_words=20, logging=True): 
    """
    test a mail for spam
    
     words_db: dict holding learnt words
     msg_db: dict holding seen meesages, keyed by Message-ID
     mail: the message, parsed to a email.message.EmailMessage
     (i.e. the "new" 3.6+ email class)
     max_words: number of most spammiest/hammiest words used
     logging: log to stdout
     
    returns floar 0<x<1 probability of spam
    """
    ham_total = 0  
    spam_total = 0  
    for m in msg_db.keys():
        if msg_db[m]:
            spam_total += 1
        else:
            ham_total += 1
    all_p = [] 
    for w in _process_mail(mail, logging):
        if w in words_db:
            _, spam_no, ham_no = words_db[w]
            pr_w_s = spam_no / spam_total
            pr_w_h = ham_no / ham_total
            pr_s_w = pr_w_s / (pr_w_h + pr_w_s)
            if pr_s_w == 0 and logging:
                print("ham 0 %r" % w)
            pr_s_w = min(0.99999, pr_s_w)
            pr_s_w = max(0.00001, pr_s_w)
            all_p.append(pr_s_w)
    if len(all_p) > max_words*2:
         all_p.sort(key=lambda n: n-0.5)
         all_p = all_p[-max_words:] + all_p[:max_words]
    p1 = p2 = 1
    for p in all_p:
        p1 *= p
        p2 *= 1 - p
    total_p = p1 / (p1 + p2)
    return total_p     
         
if __name__ == '__main__':

    def cmd_dump(ap,n,words_db,msg_db):
        ham_total = 0  
        spam_total = 0  
        for m in msg_db.keys():
            if msg_db[m]:
                spam_total += 1
            else:
                ham_total += 1
        l = [(k, words_db[k][1]/spam_total, words_db[k][2]/ham_total) for k in words_db.keys()]
        l.sort(key=lambda n: n[1]-n[2])
        for i in l[:n.words]:
            print("%s\t%.8f\t%.8f" % i)
        print("")
        for i in l[-n.words:]:
            print("%s\t%.8f\t%.8f" % i)
            
    def cmd_cleanup(ap,n, words_db, msg_db):
        cleanup(words_db)

    def cmd_probe(ap, n, words_db, msg_db):
        n_spams = n_hams = 0
        for mail in get_files(ap, n):
            try:
                score = probe(words_db, msg_db, mail, logging=n.verbose)
            except:
                traceback.print_exc()
            else:          
                if n.verbose:
                    print("Score: %.8f %s" % (score, "SPAM" if score > n.threshold else "HAM"))
                else:
                    print("%.8f" % score)
                if score > n.threshold:
                    n_spams += 1 
                else:
                    n_hams += 1
        if n.verbose:
            print("\nTotals\n------\n\nHams: %d Spams: %d" % (n_hams, n_spams))            
    
    def cmd_learn(ap, n, words_db, msg_db):
        for mail in get_files(ap, n):
            try:
                learn(words_db, msg_db, mail, n.spam, logging=n.verbose)
            except:
                traceback.print_exc()
                
                
    def get_files(ap, n):
        if n.dir:
            _files = []
            for i in n.files:
                for j in os.listdir(i):
                    _files.append(os.path.join(i,j))
            if len(_files) == 0:
                ap.error("at least one file must be provided")
        elif n.list:
            _files = []
            for line in sys.stdin.readlines():
                if line[-1] == "\n":
                    line = line[:-1]
                _files.append(line)
            if len(_files) == 0:
                ap.error("at least one file must be provided")
        else:
            _files = n.files
        if _files:
            for fname in _files:
                if n.verbose:
                    print("File: %s" % fname)
                try:
                    with open(fname, "rb") as fd:
                        mail = email.message_from_binary_file(fd, policy=default)
                        if n.verbose:
                            print("Subject: %s" % mail["Subject"])
                            print("Date: %s" % mail["Date"])
                            print("From: %s" % mail["From"])
                        yield mail
                except:
                    traceback.print_exc()
        else: 
            mail = email.message_from_binary_file(sys.stdin.buffer, policy=default)  
            if n.verbose:
                print("Subject: %s" % mail["Subject"])
                print("Date: %s" % mail["Date"])
                print("From: %s" % mail["From"])
            yield mail

            
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", "-v", action="store_true")
    subparsers = ap.add_subparsers(dest="command", title="subcommands")
    ap1 = subparsers.add_parser("probe", help="test mail for spam")
    ap1.add_argument("--threshold", "-t",  type=float, default=0.95, help="probability above which messages are considered spam")
    ap1.add_argument("--words", "-w", type=int, default=20, help="most spammiest/hammiest words used")
    g = ap1.add_mutually_exclusive_group()
    g.add_argument("--list", "-l", action="store_true", help="standard input is a list of pathnames")
    g.add_argument("--dir", "-d", action="store_true", help="input file(s) are directories")
    ap1.add_argument("files", nargs="*")
    ap1.set_defaults(func=cmd_probe)
    ap2 = subparsers.add_parser("learn", help="learn from message(s)")
    g = ap2.add_mutually_exclusive_group()
    g.add_argument("--spam", "-s", action="store_true", help="mark message(s) as spam")
    g.add_argument("--ham", "-a", action="store_false", dest="spam", help="mark message(s) as ham (non-spam)")
    g = ap2.add_mutually_exclusive_group()
    g.add_argument("--list", "-l", action="store_true", help="standard input is a list of pathnames")
    g.add_argument("--dir", "-d", action="store_true", help="input file(s) are directories")
    ap2.add_argument("files", nargs="*")
    ap2.set_defaults(func=cmd_learn)
    ap3 = subparsers.add_parser("cleanup", help="clean words database of barely-used words")
    ap3.add_argument("days", type=int, default=14, help="words not seen for this many days")
    ap3.add_argument("count", type=int, default=2, help="words below this usage count")
    ap3.set_defaults(func=cmd_cleanup)
    ap4 = subparsers.add_parser("dump", help="dump spammiest/hammiest words in database")
    ap4.add_argument("words", type=int, default=20, help="number of words to dump")
    ap4.set_defaults(func=cmd_dump)
    args = ap.parse_args()
    with shelve.open(os.path.expanduser("~/.local/spamprobe.words.db")) as words_db, shelve.open(os.path.expanduser("~/.local/spamprobe.messages.db")) as msg_db:
        if hasattr(args,"func"):
            args.func(ap, args, words_db, msg_db)
        else:
            ap.print_help()
            #pass
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
