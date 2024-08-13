/*******************************************************************************
*                                                                              *
*     Copyright (c) 2013-2017 Safenet.  All rights reserved.
*     See the attached file "CITS_Legal.pdf" for the license terms and         *
*     conditions that govern the use of this software.                         *
*                                                                              *
*     Installing, copying, or otherwise using this software indicates your     *
*     acknowledgement that you have read the license and agree to be bound     *
*     by and comply with all of its terms and conditions.                      *
*                                                                              *
*     If you do not wish to accept these terms and conditions,                 *
*     DO NOT OPEN THE FILE OR USE THE SOFTWARE."                               *
*                                                                              *
********************************************************************************/
#ifndef defs_h
#define defs_h

//-------------------------------------------------------------------
// Consistency check on the platform definitions.
// These are all of the supported platforms.  At least one of these
// macros must be defined (normally only
//-------------------------------------------------------------------
#ifndef OS_WIN32
#ifndef OS_UNIX
#ifndef OS_HPUX
#ifndef OS_HPUX_11_00
#ifndef OS_SOLARIS
#ifndef OS_AIX
#ifndef OS_LINUX
#ifndef OS_NES
#error At least one operating system target must be defined!!!!!!
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif

#if defined(OS_SOLARIS) || defined(OS_HPUX) || defined(OS_AIX) || defined(OS_LINUX) || defined(OS_HPUX_11_00)
#ifndef OS_UNIX
#define OS_UNIX
#define USE_PTHREADS
#endif
#endif

/*** Literals & Structure definitions ***************************************/
#if defined(_MSC_VER)
#if _MSC_VER > 1000
#pragma warning(disable : 4237)
#pragma warning(disable : 4068)
#endif /* _MSC_VER > 1000 */
#endif /* _MSC_VER */



/* signed integer types */
#ifdef OS_HPUX
typedef char SInt8;
typedef short SInt16;
#ifdef LUNA_LP64_CORRECT
   typedef int SInt32; /* [SHW]: was 'typedef long SInt32' (not 64-bit compiler ready).*/
#else
   typedef long SInt32; /* FIXME: with 64-bit compiler, longs are 64 bits, thus SInt32 is wrong.*/
#endif
typedef int SInt;
#else /* HPUX */
typedef signed char SInt8;
typedef signed short SInt16;
#ifdef LUNA_LP64_CORRECT
   typedef signed int SInt32; /* [SHW]: was 'typedef signed long SInt32' (not 64-bit compiler ready).*/
#else
   typedef signed long SInt32; /* FIXME: with 64-bit compiler, longs are 64 bits, thus SInt32 is wrong */
#endif
typedef signed int SInt;
#endif /* HPUX */
#if defined(OS_WIN32)
typedef signed __int64  SInt64;
#elif defined(OS_SOLARIS) || defined(OS_LINUX) || defined(OS_HPUX) || defined(OS_HPUX_11_00) || defined(OS_AIX)
typedef signed long long  SInt64;
#else
#endif

/* unsigned integer types */
typedef unsigned char UInt8;
typedef unsigned short UInt16;
#ifdef LUNA_LP64_CORRECT
typedef unsigned int UInt32; /* [SHW]: was 'typedef unsigned long UInt32' (not 64-bit compiler ready).*/
#else
typedef unsigned long UInt32; /* FIXME: with 64-bit compiler, longs are 64 bits, thus UInt32 is wrong */
#endif
typedef unsigned int UInt;
typedef unsigned long  ULong;
#if defined(OS_WIN32)
typedef unsigned __int64  UInt64;
#elif defined(OS_SOLARIS) || defined(OS_LINUX) || defined(OS_HPUX) || defined(OS_HPUX_11_00) || defined(OS_AIX)
typedef unsigned long long  UInt64;
#else
#endif

/* default integer types */
typedef char Int8;
typedef short Int16;
#ifdef LUNA_LP64_CORRECT
typedef int Int32;   /* [SHW]: was 'typedef long Int32' (not 64-bit compiler ready).*/
#else
typedef long Int32;   /* FIXME: with 64-bit compiler, longs are 64 bits, thus Int32 is wrong*/
#endif
typedef int Int;
#if defined(OS_WIN32)
typedef __int64  Int64;
#elif defined(OS_SOLARIS) || defined(OS_LINUX) || defined(OS_HPUX) || defined(OS_HPUX_11_00) || defined(OS_AIX)
typedef long long  Int64;
#else
#endif


/* floating point types */
typedef float Float32;
typedef double Float64;
typedef Float64 Float;


/* register/memory types */
typedef UInt8 Byte;
/* Added for Backwords compatibility */
typedef UInt8 BYTE;
typedef UInt16 HalfWord;
typedef UInt32 Word;

/* other types */
typedef SInt32 PointerDifference;  /* FIXME: not 64-bit compiler ready.*/
typedef UInt SizeType;  /* FIXME: not 64-bit compiler ready.*/
#ifndef nil
#define nil (0)
#endif /* nil */
//-------------------------------------------------------------------
//Setup a boolean variable type based on the platform. C++ should support
//it given that it is part of the language definition determine if compiler
//supports the bool primitive type
//-------------------------------------------------------------------


#if !defined(BOOLSUPPORT) 
#if defined(__cplusplus)

//new versions of Msc compilers support boolean
#if defined(_MSC_VER)
#if _MSC_VER >= 1100
#define BOOLSUPPORT
#endif /* _MSC_VER >= 1100 */
#endif /* _MSC_VER */

//Metrowerks compilers support boolean
#if defined(__MWERKS__)
#if __option(bool)
#define BOOLSUPPORT
#endif /* __option(bool) */
#endif /* __MWERKS__ */

#endif /* __cplusplus */
#endif /* BOOLSUPPORT */

/* boolean */
#if defined(BOOLSUPPORT) && defined(OS_WIN32)
typedef bool Boolean;
#else /* BOOLSUPPORT */
typedef UInt8 Boolean;
#if defined( OS_HPUX ) || defined( OS_AIX ) 
#define false 	0
#define true	!false
#else /* HPUX or AIX */
#if !defined(__GNUG__) && !defined(__GNUC__)
#if __SUNPRO_CC<0x500
enum { false, true };
#else /* WS 5 */

#ifndef false
#define false 0
#ifndef true
#define true !false
#endif
#endif

#endif
#endif

#endif /* HPUX */
#endif /* BOOLSUPPORT */

/* value ranges */
#define MaximumOfIntegerType(type) ((type)~(type)0 > 0 ? (type)~(type)0 : (type)~((type)1 << (sizeof(type) * 8 - 1)))
#define MinimumOfIntegerType(type) ((type)~(type)0 > 0 ? (type)0 : ((type)1 << (sizeof(type) * 8 - 1)))
#define maxSInt8 MaximumOfIntegerType(SInt8)
#define maxSInt16 MaximumOfIntegerType(SInt16)
#define maxSInt32 MaximumOfIntegerType(SInt32)
#define maxSInt MaximumOfIntegerType(SInt)
#define minSInt8 MinimumOfIntegerType(SInt8)
#define minSInt16 MinimumOfIntegerType(SInt16)
#define minSInt32 MinimumOfIntegerType(SInt32)
#define minSInt MinimumOfIntegerType(SInt)
#define maxUInt8 MaximumOfIntegerType(UInt8)
#define maxUInt16 MaximumOfIntegerType(UInt16)
#define maxUInt32 MaximumOfIntegerType(UInt32)
#define maxUInt MaximumOfIntegerType(UInt)
#define minUInt8 MinimumOfIntegerType(UInt8)
#define minUInt16 MinimumOfIntegerType(UInt16)
#define minUInt32 MinimumOfIntegerType(UInt32)
#define minUInt MinimumOfIntegerType(UInt)
#define maxInt8 MaximumOfIntegerType(UInt8)
#define maxInt16 MaximumOfIntegerType(Int16)
#define maxInt32 MaximumOfIntegerType(Int32)
#define maxInt MaximumOfIntegerType(Int)
#define minInt8 MinimumOfIntegerType(Int8)
#define minInt16 MinimumOfIntegerType(Int16)
#define minInt32 MinimumOfIntegerType(Int32)
#define minInt MinimumOfIntegerType(Int)

#define Minimum(a, b) ((a) < (b) ? (a) : (b))
#define Maximum(a, b) ((a) > (b) ? (a) : (b))
#ifndef DIM
#define DIM(a)        (sizeof(a)/sizeof(a[0]))
#endif /* DIM */

#if !defined (OS_WIN32) && !defined (OS_UNIX)
#pragma pack(1)

typedef union
{
   UInt16 offset;
   void near *pointer;
} NearPointer;

typedef union
{
   struct
   {
      UInt16 offset;
      union
      {
         UInt16 segment;
         UInt16 selector;
      };
   };
   void far *pointer;
} FarPointer;

#pragma pack()

#ifdef __cplusplus

inline UInt16 Segment(void far *farPointer)
{
   return (UInt16)((UInt32)farPointer >> 16);
}

inline UInt16 Offset(void far *farPointer)
{
   return (UInt16)(UInt32)farPointer;
}

inline UInt16 Selector(void far *farPointer)
{
   return Segment(farPointer);
}

#endif /* __cplusplus */
#endif /* _WIN32 && UNIX */

/* The following definitions are to make code portable between Win 3.x and Win 95 */
#if defined(_WINDOWS) && !defined(OS_WIN32)
#define DLL_EXPORT           _export
#else /* _WINDOWS && _WIN32 */
#define DLL_EXPORT           __declspec( dllexport )
#endif /* _WINDOWS && _WIN32 */

#ifdef OS_UNIX
	union swapper
        {
                char bytes[4];
                int words;
        };

#ifdef __cplusplus
/****************************************************************************\
*
* Function   : Swap
*
* Description: Swaps a byte from the token.
*
*****************************************************************************
*
* Arguments:   byte  - The byte to swap
*
* Return Code: UInt8 - The swapped byte
*
\****************************************************************************/
inline UInt8 Swap(UInt8 byte)
{
        swapper a;
        swapper b;
        a.words = byte;
        b.bytes[0] = a.bytes[0];
        return b.words;
 }
	
/****************************************************************************\
*
* Function   : Swap
*
* Description: Swaps a word from the token.
*
*****************************************************************************
*
* Arguments:   word     - The word to swap
*
* Return Code: UInt16   - The swapped word
*
\****************************************************************************/
inline UInt16 Swap(UInt16 word)
{
        swapper a;
        swapper b;
        a.words = word;
        b.bytes[0] = a.bytes[1];
        b.bytes[1] = a.bytes[0];
        return b.words;
 }
	
/****************************************************************************\
*
* Function   : Swap
*
* Description: Swaps a dword from the token.
*
*****************************************************************************
*
* Arguments:   dword    - The dword to swap
*
* Return Code: UInt32   - The swapped dword
*
\****************************************************************************/
inline UInt32 Swap(UInt32 dword)
{
        swapper a;
        swapper b;

        a.words = (int)dword;
        b.bytes[0] = a.bytes[3];
        b.bytes[1] = a.bytes[2];
        b.bytes[2] = a.bytes[1];
        b.bytes[3] = a.bytes[0];
        return b.words;
 }

#ifndef LUNA_LP64_CORRECT
/* FIXME: UInt and UInt32 are the same */
/****************************************************************************\
*
* Function   : Swap
*
* Description: Swaps an unsigned long word from the token.
*
*****************************************************************************
*
* Arguments:   dword    - The unsigned long to swap
*
* Return Code: UInt     - The swapped unsigned long
*
\****************************************************************************/
inline UInt Swap(UInt dword)
{
	return Swap((UInt32) dword);
}

#endif


#endif /* __cplusplus */

typedef int HANDLE;

#endif /* UNIX */

#endif /* defs_h */

/* end */

