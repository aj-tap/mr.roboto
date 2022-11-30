#! /usr/bin/env python3

"""
Mr.Roboto: Triage Automation Scripts
usage main.py -e dropbox/ -o saved_specimens/ -vt <vt-api-keys>
"""

from scripts import Analysis, Banner, Extractor

import argparse

module_name = "Mr.Roboto: Triage Automation Scripts"
__version__ = "0.0.1"


class RobotoInvoker(object):
    def __init__(self):
        self.commands = []

    def add_command(self, command):
        self.commands.append(command)

    def run(self):
        for command in self.commands:
            command.execute()


if __name__ == "__main__":
    invoker = RobotoInvoker()
    msg1 = "Blue team Automation Scripts"
    parser = argparse.ArgumentParser(prog='Mr.Roboto: ', description=msg1)
    parser.add_argument("-f", "--file", type=str, required=False, help="Set sample to analyze")
    parser.add_argument("-F", "--samples_path", type=str, required=False, help="Set file directory of Samples")
    parser.add_argument("-o", "--outputPath", type=str, required=False, help="Set output directory of Samples")
    parser.add_argument("-e", "--unzip", required=False, help="Unzip samples to output path")
    parser.add_argument("-vt", "--vt_api", type=str, help="Virus total API keys")
    args = parser.parse_args()

    if args.unzip:
        invoker.add_command(Banner.WelcomeMessage())
        invoker.add_command(Extractor.ProcessSamples(args.unzip, args.outputPath))
        invoker.add_command(Analysis.StaticAnalysis(args.outputPath))
        invoker.add_command(Analysis.Osint(args.vt_api))
    elif args.file:
        invoker.add_command(Analysis.PeStaticAnalysis(args.file, args.outputPath))
    elif args.samples_path:
        invoker.add_command(Analysis.StaticAnalysis(args.samples_path))  # perform bulk analysis
        invoker.add_command(Analysis.Osint(args.vt_api))

    invoker.run()
