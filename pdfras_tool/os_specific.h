// os_specific.h

#if defined(WIN32) || defined(WIN64) || defined (_WINDOWS)
#  define COMPILING_FOR_WIN_MSVC
#else
#  undef  COMPILING_FOR_WIN_MSVC
#endif

#if defined(WIN32) || defined(WIN64) || defined (_WINDOWS)
#  define COMPILING_FOR_WIN
#else
#  undef  COMPILING_FOR_WIN
#endif

#ifdef COMPILING_FOR_WIN_MSVC
#	define STRICMP _stricmp
#	define ACCESS _access
#	define ACCESS_READ 04
#else
#	define STRICMP stricmp
#	define ACCESS access
#	define ACCESS_READ R_OK
#endif