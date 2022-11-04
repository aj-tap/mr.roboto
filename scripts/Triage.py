import hashlib
import pandas as pd
import os
import virustotal_python as vt
import json
import yara


class Samples:
    def __init__(self, file_dir_path="dropbox/", vt_api=None, file_dir_output_path="reports/"):
        self.file_dir_path = file_dir_path
        self.file_dir_output_path = file_dir_output_path
        self.vt_api = vt_api
        # self.data = {"directory_path": [], "file_names": [], "hashes": []}
        self.data = pd.DataFrame.from_dict({
            'File_Name': [],
            'md5': [],
            'sha256': [],
            'Dir_Path': []
        })

    def getHashes(self):
        for i in range(self.data.shape[0]):
            filename = self.data.at[i, 'Dir_Path'] + "/" + self.data.at[i, 'File_Name']
            with open(filename, "rb") as f:
                bytes_of_file = f.read()  # read entire file as bytes
                self.data.at[i, 'md5'] = hashlib.md5(bytes_of_file).hexdigest()
                self.data.at[i, 'sha256'] = hashlib.sha256(bytes_of_file).hexdigest()

    def getFiles(self):
        for dirPath, dirNames, fileNames in os.walk(self.file_dir_path):
            if len(fileNames) > 1:
                for f in fileNames:
                    self.data.loc[len(self.data)] = [f, "", "", dirPath]
            if fileNames:
                self.data.loc[len(self.data)] = [fileNames[0], "", "", dirPath]

    def getVTreport(self):
        for i in range(self.data.shape[0]):
            file_hash = self.data.at[i, 'sha256']
            output_path = self.file_dir_output_path + self.data.at[i, 'File_Name']
            with vt.Virustotal(self.vt_api) as virus_total:
                resp = virus_total.request(f"files/{file_hash}")
                print(resp.data["links"]["self"])
                print(resp.data["attributes"]["total_votes"])
                filename = 'VT_' + file_hash + '.json'
                # To be refactored
                if not os.path.exists(output_path):
                    os.makedirs(output_path)
                with open(os.path.join(output_path, filename), 'w') as temp_file:
                    temp_file.write(json.dumps(resp.data, sort_keys=True, indent=4))

    def getYara(self, yara_rule_path):
        # To be refactored and fix naming convention
        for i in range(self.data.shape[0]):
            file_path = self.data.at[i, 'Dir_Path'] + "/" + self.data.at[i, 'File_Name']
            print(self.data.at[i, 'File_Name'])
            with open(file_path, 'rb') as f:
                for root, dirNames, ruleNames in os.walk(yara_rule_path):
                    for rule in ruleNames:
                        if rule.endswith('.yar'):
                            try:
                                rules = yara.compile(str(os.path.join(root, rule)))
                                print(str(os.path.join(root, rule)))
                                matches = yara.Rules.match(rules, data=f.read())
                                for match in matches:
                                    if match.rule:
                                        print(match.rule)
                            except yara.SyntaxError as e:
                                # print(e)
                                pass
