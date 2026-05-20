#!/usr/bin/python
import os
import sys
from pathlib import Path
import xml.etree.ElementTree as ET
from datetime import datetime

out_tree = ET.ElementTree()
out_doc = ET.Element('valgrind_trace')
summary_el = ET.SubElement(out_doc, "summary")
all_count = 0
sumTotalErrors = 0
sumSyscallParam = 0
sumLeak_StillReachable = 0
sumLeak_PossiblyLost = 0
sumLeak_IndirectlyLost = 0
sumLeak_DefinitelyLost = 0
sumInvalidWrite = 0
sumInvalidRead = 0
def display_file(file):
    error = 0
    try:
        tree = ET.parse(file)
        root = tree.getroot()
    except ET.ParseError as e:
        error = 1
    if error==0:
        process_el = ET.SubElement(summary_el, "process")
        TotalErrors = 0
        SyscallParam = 0
        Leak_StillReachable = 0
        Leak_PossiblyLost = 0
        Leak_IndirectlyLost = 0
        Leak_DefinitelyLost = 0
        InvalidWrite = 0
        InvalidRead = 0
        global all_count
        global sumTotalErrors
        global sumSyscallParam
        global sumLeak_StillReachable
        global sumLeak_PossiblyLost
        global sumLeak_IndirectlyLost
        global sumLeak_DefinitelyLost
        global sumInvalidWrite
        global sumInvalidRead
        for error in root.iter("error"):
            TotalErrors += 1  
            sumTotalErrors += 1    
            error_el = ET.SubElement(out_doc, "error")
            error_el.set("process", root.find("args/argv/exe").text)
            hex = error.find("unique").text
            dec = int(hex, 16)
            error_el.set("unique_hex", hex)
            error_el.set("unique_dec", str(dec))
            kind = error.find("kind").text
            error_el.set("kind", kind )
            if kind == "SyscallParam" :
                SyscallParam += 1
                sumSyscallParam += 1
            elif kind == "Leak_StillReachable" :
                Leak_StillReachable += 1
                sumLeak_StillReachable += 1
            elif kind == "Leak_PossiblyLost" :
                Leak_PossiblyLost += 1
                sumLeak_PossiblyLost += 1
            elif kind == "Leak_IndirectlyLost" :
                Leak_IndirectlyLost += 1
                sumLeak_IndirectlyLost += 1
            elif kind == "Leak_DefinitelyLost" :
                Leak_DefinitelyLost += 1
                sumLeak_DefinitelyLost += 1
            elif kind == "InvalidWrite" :
                InvalidWrite += 1
                sumInvalidWrite += 1
            elif kind == "InvalidRead" :
                InvalidRead += 1
                sumInvalidRead += 1
            
            leakedbytes = error.find("xwhat/leakedbytes")
            if leakedbytes is None:
                error_el.set("leakedbytes", "0")
            else:
                error_el.set("leakedbytes", leakedbytes.text)
            leakedblocks = error.find("xwhat/leakedblocks")
            if leakedblocks is None:
                error_el.set("leakedblocks", "0")
            else:
                error_el.set("leakedblocks", leakedblocks.text)
            
            frame_order = 0;
            for frame in error.iterfind("stack/frame"):
                frame_el = ET.SubElement(error_el, "frame")
                frame_el.set("all_count", str(all_count))
                all_count = all_count + 1
                frame_el.set("ip", frame.find("ip").text)
                frame_el.set("order", str(frame_order))
                obj = frame.find("obj")
                if obj is None:
                    frame_el.set("obj", "NA")
                else:
                    frame_el.set("obj", obj.text)

                fn = frame.find("fn")
                if fn is None:
                    frame_el.set("fn", "NA")
                else:
                    frame_el.set("fn", fn.text)

                dir = frame.find("dir")
                if dir is None:
                    frame_el.set("dir", "NA")
                else:
                    frame_el.set("dir", dir.text)

                file = frame.find("file")
                if file is None:
                    frame_el.set("file", "NA")
                else:
                    frame_el.set("file", file.text)

                line = frame.find("line")
                if line is None:
                    frame_el.set("line", "0")
                else:
                    frame_el.set("line", line.text)

                frame_order = frame_order + 1
        process_el.set("name", root.find("args/argv/exe").text)
        process_el.set("TotalErrors", str(TotalErrors))   
        process_el.set("SyscallParam", str(SyscallParam))
        process_el.set("Leak_StillReachable", str(Leak_StillReachable))
        process_el.set("Leak_PossiblyLost", str(Leak_PossiblyLost))
        process_el.set("Leak_IndirectlyLost", str(Leak_IndirectlyLost))
        process_el.set("Leak_DefinitelyLost", str(Leak_DefinitelyLost))
        process_el.set("InvalidWrite", str(InvalidWrite))
        process_el.set("InvalidRead", str(InvalidRead))

xml_dir = sys.argv[1]

xml_files = [f for f in os.listdir(xml_dir) if os.path.isfile(xml_dir + os.sep + f)]
for filename in xml_files:
    xml_path = os.path.join(xml_dir, filename)
    name, extension = os.path.splitext(filename)
    if (extension == ".xml"):
        display_file(xml_path)

summary_el.set("TotalErrors", str(sumTotalErrors))   
summary_el.set("SyscallParam", str(sumSyscallParam))
summary_el.set("Leak_StillReachable", str(sumLeak_StillReachable))
summary_el.set("Leak_PossiblyLost", str(sumLeak_PossiblyLost))
summary_el.set("Leak_IndirectlyLost", str(sumLeak_IndirectlyLost))
summary_el.set("Leak_DefinitelyLost", str(sumLeak_DefinitelyLost))
summary_el.set("InvalidWrite", str(sumInvalidWrite))
summary_el.set("InvalidRead", str(sumInvalidRead))
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
summary_el.set("Date", now)
ET.indent(out_doc, space='  ', level=0)
ET.dump(out_doc)

# process_name
# error_unique_dec
# error_unique_hex
# error_kind
# error_leaked_bytes
# error_leaked_blocks
# frame_order
# frame_ip
# frame_obj
# frame_fn
# frame_dir
# frame_file
# frame_line
