#ifndef _H_Platform
#define _H_Platform
#pragma once

#include <stddef.h>
#include <math.h>

#ifdef WIN32
#define PDPLATFORM "WIN32"
typedef char pdint8;
typedef unsigned char pduint8;
typedef short pdint16;
typedef unsigned short pduint16;
typedef long pdint32;
typedef unsigned long pduint32;
typedef unsigned long long int pduint64;
typedef float pdfloat32;
typedef double pddouble;
typedef pduint32 pdbool;
#define PDFRASAPICALL __cdecl

#define PDDEBUG _DEBUG
#define PD_FALSE ((pdbool)0)
#define PD_TRUE ((pdbool)!0)

#include <time.h>
#include <sys\timeb.h>
#include <float.h>

#define pdisinf(x) (!_finite(x))
#define pdisnan(x) (_isnan(x))

#endif

#ifndef PDPLATFORM

# include  <stdint.h>
# include  <time.h>
#define PDPLATFORM "GENERIC"
typedef int8_t pdint8;
typedef uint8_t pduint8;
typedef int16_t pdint16;
typedef uint16_t pduint16;
typedef int32_t pdint32;
typedef uint32_t pduint32;
#define PDFRASAPICALL

typedef float pdfloat32;
typedef double pddouble;
typedef int pdbool;

#define pdisinf(x) isinf(x)
#define pdisnan(x) isnan(x)

#define PDDEBUG _DEBUG
#define PD_FALSE ((pdbool)0)
#define PD_TRUE ((pdbool)!0)
#endif
#endif
