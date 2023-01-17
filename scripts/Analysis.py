import json
from pprint import pprint
import pefile
import virustotal_python as vt
import pandas as pd
import hashlib
import os


class StaticAnalysis:
    def __init__(self, sample_path):
        #  self.output_path = output_path
        self.sample_path = str(sample_path)
        self.specimens_table = pd.DataFrame.from_dict({
            'File_Name': [],
            'md5': [],
            'sha1': [],
            'sha256': [],
            'Dir_Path': []
        })

    def enumerateSamples(self):
        for dirPath, dirNames, fileNames in os.walk(self.sample_path):
            if len(fileNames) > 1:
                for f in fileNames:
                    self.specimens_table.loc[len(self.specimens_table)] = [f, "", "", "", dirPath]
            if fileNames:
                self.specimens_table.loc[len(self.specimens_table)] = [fileNames[0], "", "", "", dirPath]

    def getHashes(self):
        for i in range(self.specimens_table.shape[0]):
            filename = self.specimens_table.at[i, 'Dir_Path'] + "/" + self.specimens_table.at[i, 'File_Name']
            with open(filename, "rb") as f:
                bytes_of_file = f.read()  # read entire file as bytes
                self.specimens_table.at[i, 'md5'] = hashlib.md5(bytes_of_file).hexdigest()
                self.specimens_table.at[i, 'sha1'] = hashlib.sha1(bytes_of_file).hexdigest()
                self.specimens_table.at[i, 'sha256'] = hashlib.sha256(bytes_of_file).hexdigest()

    def getStrings(self, length=8):
        for i in range(self.specimens_table.shape[0]):
            filename = os.path.join(self.specimens_table.at[i, 'Dir_Path'], self.specimens_table.at[i, 'File_Name'])
            output_file = os.path.join(self.specimens_table.at[i, 'Dir_Path'], "strings.txt")
            cmd = "flarestrings -n " + str(length) + " " + filename + " | rank_strings --scores > " + output_file
            try:
                os.system(cmd)
                print("Pulling strings " + filename)
            except ValueError as e:
                print(e)

    def getCapaResult(self):
        for i in range(self.specimens_table.shape[0]):
            filename = os.path.join(self.specimens_table.at[i, 'Dir_Path'], self.specimens_table.at[i, 'File_Name'])
            output_file = os.path.join(self.specimens_table.at[i, 'Dir_Path'], "capa-result.txt")
            capa_location = os.path.join(os.getcwd(), "util")
            capa_location = os.path.join(capa_location, "capa")
            print("capa for sample: " + filename)
            # cmd = "." + capa_location + " " + filename + " >" + output_file
            cmd = "./util/capa " + filename + " >" + output_file
            os.system(cmd)

    def execute(self):
        print("------------------\n")
        print("Enumerating Samples\n")
        self.enumerateSamples()
        print("------------------\n")
        print("Getting hashes\n")
        print("------------------\n")
        self.getHashes()
        # Print samples
        print(self.specimens_table[['File_Name', 'sha256']].to_string(index=False))
        print("------------------\n")
        print("Pulling Strings")
        print("------------------\n")
        self.getStrings()
        print("------------------\n")
        print("Calling Capa")
        print("------------------\n")
        self.getCapaResult()
        print("------------------\n")
        print("Saving result in pkl")
        if os.path.isfile("analysis.pkl"):
            os.remove("analysis.pkl")
        self.specimens_table.to_pickle("analysis.pkl")


class PeStaticAnalysis:
    def __init__(self, file_path, output_path):
        self.output_path = output_path
        self.pe_sample = pefile.PE(file_path)

    def getAllInfo(self):
        print(self.pe_sample.dump_info())

    def getImportantFields(self):
        print("Machine : ", hex(self.pe_sample.FILE_HEADER.Machine))
        print("Number of sections : ", self.pe_sample.FILE_HEADER.NumberOfSections)
        print("TimeDateStamp : ", hex(self.pe_sample.FILE_HEADER.TimeDateStamp))
        print("Characteristics :", hex(self.pe_sample.FILE_HEADER.Characteristics))
        if self.pe_sample.PE_TYPE == 0x10b:
            print("PEType: PE32")
        elif self.pe_sample.PE_TYPE == 0x20b:
            print("PEType: PE64")
        print("ImageBase : ", self.pe_sample.OPTIONAL_HEADER.ImageBase)
        print("SizeOfCode : ", self.pe_sample.OPTIONAL_HEADER.SizeOfCode)
        print("FileAlignment : ", self.pe_sample.OPTIONAL_HEADER.FileAlignment)
        print("SectionAlignment : ", self.pe_sample.OPTIONAL_HEADER.SectionAlignment)

    def getImpHash(self):
        print("Import Hash: ", self.pe_sample.get_imphash())

    def getImportSymbols(self):
        self.pe_sample.parse_data_directories()
        for entry in self.pe_sample.DIRECTORY_ENTRY_IMPORT:
            print(entry.dll)
            for imp in entry.imports:
                print('\t', hex(imp.address), imp.name)

    def getExportSymbols(self):
        for exp in self.pe_sample.DIRECTORY_ENTRY_EXPORT.symbols:
            print(hex(self.pe_sample.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)

    def getSections(self):
        print("Section Name \t Virtual Address \t Virtual Size \t SizeOfRawData")
        for section in self.pe_sample.sections:
            print(section.Name, hex(section.VirtualAddress),
                  hex(section.Misc_VirtualSize), section.SizeOfRawData)

    def execute(self):
        self.getImportantFields()
        self.getImpHash()
        self.getImportSymbols()
        # self.getExportSymbols()
        self.getSections()


class Osint:
    def __init__(self, vt_api, specimens_table="analysis.pkl"):
        self.specimens_table = specimens_table
        self.vt_api = vt_api

    def getVTreport(self):
        specimens_table = pd.read_pickle(self.specimens_table)
        for i in range(specimens_table.shape[0]):
            file_hash = specimens_table.at[i, 'sha256']
            output_path = os.path.join(specimens_table.at[i, 'Dir_Path'])

            with vt.Virustotal(self.vt_api) as virus_total:
                try:
                    resp = virus_total.request(f"files/{file_hash}")
                    print("--------------------------\n Generating VT report for Sample: " + file_hash)
                    print(resp.data["attributes"]["meaningful_name"])
                    # print(resp.data["attributes"]["detectiteasy"]["filetype"])
                    print(resp.data["attributes"]["total_votes"])
                    print(resp.data["links"]["self"])
                    filename = 'VT_Report_' + file_hash + '.json'
                    if not os.path.exists(output_path):
                        os.makedirs(output_path)
                    with open(os.path.join(output_path, filename), 'w') as temp_file:
                        temp_file.write(json.dumps(resp.data, sort_keys=True, indent=4))
                except Exception as e:
                    print(e)
                    pass

    def execute(self):
        self.getVTreport()
