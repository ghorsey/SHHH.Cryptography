'''
Created on Nov 2, 2012

@author: Geoff
'''
import os
import shutil
import sys
import fnmatch
import walklevel

def removeDir(path):
    print 'Removing {0}'.format(path)
    shutil.rmtree(path)

maxDepth = 1
if len(sys.argv) == 2:
    maxDepth = int(sys.argv[1])
    
print maxDepth
for root, dirNames, filenames in walklevel.walklevel(".\\", level = maxDepth):
    for dir in fnmatch.filter(dirNames, "bin"):
        try:
            removeDir(os.path.join(root, dir))
        except:
            print "Failed: " + os.path.join(root, dir)
    for dir in fnmatch.filter(dirNames, "obj"):
        try:
            removeDir(os.path.join(root, dir))
        except:
            print "Failed: " + os.path.join(root, dir)