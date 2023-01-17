import hashlib
import os
import json
import shutil
# from zipfile import ZipFile, ZIP_LZMA
import pyzipper
import pandas as pd


class ProcessSamples:
    def __init__(self, sample_path, output_path):
        self.sample_path = str(sample_path)
        self.output_path = str(output_path)
        self.zip_files_pwd = "infected"
        self.data = pd.DataFrame.from_dict({
            'File_name': [],
            'Dir_path': []
        })

    def getFiles(self):
        for dirPath, dirNames, fileNames in os.walk(self.sample_path):
            if len(fileNames) > 1:
                for f in fileNames:
                    self.data.loc[len(self.data)] = [f, dirPath]  # set file name
            if fileNames:
                self.data.loc[len(self.data)] = [fileNames[0], dirPath]  # set dir path

    def extractFiles(self):
        if os.path.exists(self.output_path):
            shutil.rmtree(self.output_path)
        for dirPath, dirNames, fileNames in os.walk(self.sample_path):
            for f in fileNames:
                path = os.path.join(self.output_path, f.removesuffix(".zip"))
                current_file = os.path.join(dirPath, f)
                #os.makedirs(path)
                if f.endswith(".zip"):
                    with pyzipper.AESZipFile(current_file, 'r', compression=pyzipper.ZIP_DEFLATED,
                                             encryption=pyzipper.WZ_AES) as zp:
                        try:
                            zp.extractall(path, pwd=str.encode(self.zip_files_pwd))
                            print(f + "is extracted at " + path)
                        except NotImplementedError as e:
                            print(current_file + " " + str(e))
                            pass
                else:
                    shutil.copy(current_file, path)
                    print(f + "is moved at " + os.path.join(path, f))

    def execute(self):
        self.extractFiles()
