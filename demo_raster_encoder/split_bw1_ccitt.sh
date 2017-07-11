#!/bin/sh

convert -density 300x300 "sample bw1 ccitt.pdf" -compress Group4 bw1_ccitt.tif
convert bw1_ccitt.tif -crop 2521x1000 -compress Group4 +repage bw1_ccitt_2521x1000_%d.tif
mv bw1_ccitt_2521x1000_3.tif bw1_ccitt_2521x0279_3.tif

dd if=bw1_ccitt_2521x1000_0.tif of=bw1_ccitt_2521x1000_0.bin bs=1 skip=8 count=13915
dd if=bw1_ccitt_2521x1000_1.tif of=bw1_ccitt_2521x1000_1.bin bs=1 skip=8 count=16688
dd if=bw1_ccitt_2521x1000_2.tif of=bw1_ccitt_2521x1000_2.bin bs=1 skip=8 count=2186
dd if=bw1_ccitt_2521x0279_3.tif of=bw1_ccitt_2521x0279_3.bin bs=1 skip=8 count=695

for i in $( ls bw1_ccitt_2521x*.bin ); do
    xxd -i $i > $i.h
done

rm -f bw1_ccitt_strip_data.h 
cat bw1_ccitt_2521x*.bin.h > bw1_ccitt_strip_data.h 

rm -f bw1_ccitt.tif
rm -f bw1_ccitt_2521*.tif
rm -f bw1_ccitt_2521*.bin
rm -f bw1_ccitt_2521*.bin.h

unix2dos bw1_ccitt_strip_data.h
