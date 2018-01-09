// PdfDate.c - date and time functions

#include <time.h>
#include <stdio.h>

#include "PdfDate.h"
#include "PdfPlatform.h"
#include "PdfAlloc.h"

struct t_date {
    pduint8 hour;
    pduint8 minute;
    pduint8 secs;
    pduint8 day;
    pduint8 month;
    pduint16 year;
    pdint8 hour_offset;
    pdint8 mins_offset;

    t_pdmempool* pool;
};

t_date* pd_date_create_current_localtime(t_pdmempool* inpool) {
    time_t t;
    time(&t);

    struct tm* local = localtime(&t);

    t_date* d = (t_date*)pd_alloc(inpool, sizeof(t_date));
    d->pool = inpool;

    d->day = local->tm_mday;
    d->month = local->tm_mon + 1;
    d->year = local->tm_year + 1900;
    d->hour = local->tm_hour;
    d->minute = local->tm_min;
    d->secs = local->tm_sec;
    
    struct tm* global = gmtime(&t);
    d->hour_offset = d->hour - global->tm_hour;
    d->mins_offset = 0;

    return d;
}

void pd_date_destroy(t_date* date) {
    pd_free(date);
    date = NULL;
}

char* pd_date_to_pdfstring(t_date* date) {
    char* ret = (char*)pd_alloc(date->pool, sizeof(char) * 25);

    char O;
    pdint8 hour_offset = date->hour_offset;
    if (hour_offset < 0) {
        O = '-';
        hour_offset = hour_offset * -1;
    }
    else if (hour_offset > 0)
        O = '+';
    else
        O = 'Z';

    sprintf(ret, "D:%d%02d%02d%02d%02d%02d%c%02d'%02d'", date->year, date->month, date->day, date->hour, date->minute, date->secs, O, hour_offset, date->mins_offset);

    return ret;
}
