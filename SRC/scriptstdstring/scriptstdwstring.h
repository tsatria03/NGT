//
// Script std::wstring
//
// This function registers the std::wstring type with AngelScript to be used as the UTF16 string type.
//
// The wstring type is registered as a value type, thus may have performance issues if a lot of 
// wstring operations are performed in the script. However, for relatively few operations, this should
// not cause any problem for most applications.
//

#ifndef SCRIPTSTDWSTRING_H
#define SCRIPTSTDWSTRING_H

#ifndef ANGELSCRIPT_H 
// Avoid having to inform include path if header is already include before
#include <angelscript.h>
#endif

#include <string>

//---------------------------
// Compilation settings
//

// Sometimes it may be desired to use the same method names as used by C++ STL.
// This may for example reduce time when converting code from script to C++ or
// back.
//
//  0 = off
//  1 = on
#ifndef AS_USE_STLNAMES
#define AS_USE_STLNAMES 0
#endif

// Some prefer to use property accessors to get/set the length of the string
// This option registers the accessors instead of the method length()
#ifndef AS_USE_ACCESSORS
#define AS_USE_ACCESSORS 0
#endif

// This option disables the implicit operators with primitives
#ifndef AS_NO_IMPL_OPS_WITH_STRING_AND_PRIMITIVE
#define AS_NO_IMPL_OPS_WITH_STRING_AND_PRIMITIVE 0
#endif

BEGIN_AS_NAMESPACE

void RegisterStdWstring(asIScriptEngine* engine);

END_AS_NAMESPACE

#endif
