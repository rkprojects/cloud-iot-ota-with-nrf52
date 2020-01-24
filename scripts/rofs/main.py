#
# Copyright 2019-2020 Ravikiran Bukkasagara <contact@ravikiranb.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#    
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Description:
Generates readonly data structure representing files.

Some files might be required to stored as null terminated strings. 
Append extensions of such files to list: null_termination_required
"""

from pathlib import Path
import os
import sys
from datetime import datetime
import mimetypes

mimetypes.init()

# files which needs to be null terminated. like PEM encoded files X506 certificates.
null_termination_required = [".pem", ".json"]

app_dir = Path("../../app")
root_dir = app_dir / "rofs_root"
if not root_dir.exists():
    print("Directory '{0}' not found. Please create it and copy required files in it.".format(str(root_dir)))
    sys.exit()

src = app_dir / "src/rofs_generated.c"
   

code = "/*\nAuto generated source code on " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
code += "Source Directory: {}\n*/\n\n".format(str(root_dir.resolve()))
code += '#include "rofs.h"\n\n'
code += "const unsigned char rofs_data[] = {\n"

info_struct = "const rofs_file_info_t rofs_index_table[] = {\n"

src_f = open(str(src), "w")
src_f.write(code) 
index = 0
count = 0
for p in root_dir.glob('**/*'):
    if p.is_file():
        target_path = '/' + p.relative_to(root_dir).as_posix()
        target_length = p.stat().st_size
        try:
            mime_type_name = mimetypes.types_map[p.suffix]
        except Exception as e:
            mime_type_name = "application/octet-stream"
            pass
            
        add_null = 0
        if p.suffix in null_termination_required:
            add_null = 1
            
        info_struct += '\t{{"{0}", {1}, {2}, {3}, "{4}"}},\n'.format(target_path, index, target_length, add_null, mime_type_name)
        code = "\t/* filepath = {0}, index = {1}, length = {2}, null_added = {3} */\n\t".format(target_path, index, target_length, add_null)
        src_f.write(code)
        with open(str(p), "rb") as f:
            byte = f.read(1)
            while byte != b"":
                src_f.write(hex(ord(byte)) + ', ') 
                byte = f.read(1)
            if add_null:
                src_f.write(hex(0) + ', ')
            src_f.write('\n') 
        index = index + target_length + add_null
        count += 1
        print("Added rofs path: {0}".format(target_path))

code =  "}}; /* Total Length = {0} */\n\n".format(index)        
src_f.write(code)
info_struct += "\t{0, 0, 0}\n};\n"
src_f.write(info_struct)
src_f.close()

print(count, "Read only files generated in", src)
