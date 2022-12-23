#! /usr/bin/env python3

"""
Mr.Roboto: Malware Analysis Scripts
usage main.py -e dropbox/ -o saved_specimens/ -vt <vt-api-keys>
"""
import sys

from scripts import Analysis, Banner, Extractor

import argparse

module_name = "Mr.Roboto: Malware Analysis Scripts"
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
    msg1 = "Malware analysis scripts"
    parser = argparse.ArgumentParser(prog='Mr.Roboto: ', description=msg1)
    parser.add_argument("-p", "--peAnalysis", type=str, required=False, help="Set sample to analyze")
    parser.add_argument("-f", "--samplesPath", required=False, type=str, help="Set file directory of samples")
    parser.add_argument("-o", "--outputPath", type=str, required=False, help="Set output directory of samples")
    # parser.add_argument("-e", "--unzip", required=False, help="Unzip samples to output path")
    parser.add_argument('-e', "--unzip", action='store_true', help="Enable extraction of zip files")
    parser.add_argument("-vt", "--vt_api", type=str, help="Virus total API keys")

    args = parser.parse_args()

    invoker.add_command(Banner.WelcomeMessage())
    # Unzip Routine
    if args.unzip is not None:
        invoker.add_command(Extractor.ProcessSamples(args.samplesPath, args.outputPath))
    # Perform triage
    if args.samplesPath is not None:
        invoker.add_command(Analysis.StaticAnalysis(args.outputPath))
        if args.samplesPath is not None:
            invoker.add_command(Analysis.Osint(args.vt_api))

    # PE static analysis
    elif args.peAnalysis is not None:
        invoker.add_command(Analysis.PeStaticAnalysis(args.file, args.outputPath))
    # Perform Osint Query DB
    # elif args.vt_api is not None:
    # invoker.add_command(Analysis.Osint(args.vt_api))

    if len(sys.argv) == 0:
        parser.print_help(sys.stderr)
        sys.exit(1)
    invoker.run()
