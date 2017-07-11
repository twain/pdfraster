#!/bin/sh

convert gray8_page.jpg -crop 850x200 +repage gray8_page_850x200_%d.jpg
mv gray8_page_850x200_5.jpg gray8_page_850x100_5.jpg

for i in $( ls gray8_page_850*jpg ); do
    xxd -i $i > $i.h
done

rm -f gray8_page_strip.h
cat gray8_page_850x*.jpg.h > gray8_page_strip.h
 
rm -f gray8_page_850x*.jpg
rm -f gray8_page_850x*.jpg.h

unix2dos gray8_page_strip.h
