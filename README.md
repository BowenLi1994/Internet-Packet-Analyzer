# Internet-Packet-Analyzer

## Purpose
 - 1. Experience with packet analyzing and Internet packet formats.

## Instructions
1. Type "make" to compile the file
2. For panalyzer, I implemented 4 flags: no flag, -v, -V, -c <number> .
   - ./panalyzer filesname: to run the summary of the file
   - ./panalyzer -c number filesname: to show the number of the summary of the file
   - ./panalyzer -v filesname: to show the basic verbose mode
   - ./panalyzer -V filesname: to show the extended verbose mode
3. For the diff, if diff the result of the summary, you should use
   - diff -b to ignore the spacing
