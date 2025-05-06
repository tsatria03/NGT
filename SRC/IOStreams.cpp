#include <angelscript.h>
#include <assert.h>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector> 

#ifdef GetObject
#undef GetObject
#endif

using namespace std;

class CScriptIOStream;
static int g_stringTypeId = -1;

const int SCRIPT_EOF_VALUE = -1;


class CScriptIOStream {
public:
	std::ostream* outputStream_;
	std::istream* inputStream_;

	CScriptIOStream(bool isStatic = false)
		: ref_(1),
		outputStream_(&internalStringStream_),
		inputStream_(&internalStringStream_),
		isProperStringStream_(true),
		isStatic_(isStatic) {
	}

	CScriptIOStream(std::ostream* os, std::istream* is, bool isStatic = false)
		: ref_(1),
		outputStream_(os),
		inputStream_(is),
		isProperStringStream_(false),
		isStatic_(isStatic) {
	}

	~CScriptIOStream() {
	}

	void AddRef() {
		ref_++;
	}

	void Release() {
		if (--ref_ == 0 && !isStatic_) {
			delete this;
		}
	}

	// --- Output Methods ---
	void write(const string& data) {
		if (outputStream_) {
			(*outputStream_) << data;
		}
		else {
			asIScriptContext* ctx = asGetActiveContext();
			if (ctx) ctx->SetException("Attempt to write to a null output stream.");
		}
	}

	void put(int8_t ch) {
		if (outputStream_) {
			outputStream_->put(static_cast<char>(ch));
		}
		else {
			asIScriptContext* ctx = asGetActiveContext();
			if (ctx) ctx->SetException("Attempt to put char to a null output stream.");
		}
	}

	void flush() {
		if (outputStream_) {
			outputStream_->flush();
		}
		// No exception if null, flush on null is a no-op.
	}

	// --- Input Methods ---
	string read() { // Reads a word
		string data;
		if (inputStream_) {
			(*inputStream_) >> data;
		}
		else {
			asIScriptContext* ctx = asGetActiveContext();
			if (ctx) ctx->SetException("Attempt to read from a null input stream.");
		}
		return data;
	}

	string getline() {
		string data;
		if (inputStream_) {
			std::getline(*inputStream_, data);
		}
		else {
			asIScriptContext* ctx = asGetActiveContext();
			if (ctx) ctx->SetException("Attempt to getline from a null input stream.");
		}
		return data;
	}

	int32_t get() {
		if (inputStream_) {
			return inputStream_->get();
		}
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) ctx->SetException("Attempt to get char from a null input stream.");
		return SCRIPT_EOF_VALUE;
	}

	int32_t peek() {
		if (inputStream_) {
			return inputStream_->peek();
		}
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) ctx->SetException("Attempt to peek char from a null input stream.");
		return SCRIPT_EOF_VALUE;
	}

	void ignore(asUINT count = 1, int32_t delim = SCRIPT_EOF_VALUE) {
		if (inputStream_) {
			// EOF in C++ streams is usually std::char_traits<char>::eof()
			// which is typically -1. So SCRIPT_EOF_VALUE (-1) should work.
			inputStream_->ignore(static_cast<std::streamsize>(count), static_cast<int>(delim));
		}
		else {
			asIScriptContext* ctx = asGetActiveContext();
			if (ctx) ctx->SetException("Attempt to ignore on a null input stream.");
		}
	}

	void unget() {
		if (inputStream_) {
			// Check if unget is possible
			if (inputStream_->good() || inputStream_->eof()) {
				inputStream_->unget();
				// After unget, eof bit might be cleared if it was set due to trying to read past end.
				// Standard says unget() on a stream where gptr() == eback() is undefined, 
				// but most implementations handle one char unget after successful read.
			}
			else {
				asIScriptContext* ctx = asGetActiveContext();
				if (ctx) ctx->SetException("Cannot unget from stream in current state (e.g. badbit or failbit set, or no character read prior).");
			}
		}
		else {
			asIScriptContext* ctx = asGetActiveContext();
			if (ctx) ctx->SetException("Attempt to unget on a null input stream.");
		}
	}

	// --- Stream State Methods ---
	bool good() const {
		if (inputStream_) return inputStream_->good();
		if (outputStream_) return outputStream_->good();
		return false; // If both are null, not good.
	}

	bool eof() const {
		if (inputStream_) return inputStream_->eof();
		return true;
	}

	bool fail() const {
		bool inputFailed = inputStream_ ? inputStream_->fail() : false;
		bool outputFailed = outputStream_ ? outputStream_->fail() : false;
		return inputFailed || outputFailed;
	}

	bool bad() const {
		bool inputBad = inputStream_ ? inputStream_->bad() : false;
		bool outputBad = outputStream_ ? outputStream_->bad() : false;
		return inputBad || outputBad;
	}

	void clear_flags() {
		if (inputStream_) inputStream_->clear();
		if (outputStream_) outputStream_->clear();
	}

	// --- Seeking Methods ---
	void seekg(asUINT pos) {
		if (inputStream_) {
			inputStream_->seekg(static_cast<std::streampos>(pos));
		}
		else {
			asIScriptContext* ctx = asGetActiveContext();
			if (ctx) ctx->SetException("Attempt to seekg on a null input stream.");
		}
	}

	asUINT tellg() {
		if (inputStream_) {
			std::streampos sPos = inputStream_->tellg();
			if (sPos == static_cast<std::streampos>(-1)) { // Error in tellg
				return static_cast<asUINT>(-1); // Or set script exception
			}
			return static_cast<asUINT>(sPos);
		}
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) ctx->SetException("Attempt to tellg on a null input stream.");
		return static_cast<asUINT>(-1);
	}

	void seekp(asUINT pos) {
		if (outputStream_) {
			outputStream_->seekp(static_cast<std::streampos>(pos));
		}
		else {
			asIScriptContext* ctx = asGetActiveContext();
			if (ctx) ctx->SetException("Attempt to seekp on a null output stream.");
		}
	}

	asUINT tellp() {
		if (outputStream_) {
			std::streampos sPos = outputStream_->tellp();
			if (sPos == static_cast<std::streampos>(-1)) { // Error in tellp
				return static_cast<asUINT>(-1);
			}
			return static_cast<asUINT>(sPos);
		}
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) ctx->SetException("Attempt to tellp on a null output stream.");
		return static_cast<asUINT>(-1);
	}

	// --- StringStream Specific Methods ---
	string str() {
		if (isProperStringStream_) {
			return internalStringStream_.str();
		}
		// Try to get string from external stringstream if applicable (requires RTTI)
#ifdef __GXX_RTTI 
// dynamic_cast is only available if RTTI is enabled.
// Check if outputStream_ is actually a stringstream
		if (auto* ss_ptr = dynamic_cast<std::stringstream*>(outputStream_)) {
			return ss_ptr->str();
		}
		// Check if inputStream_ is actually a stringstream (less common for str())
		if (auto* ss_ptr = dynamic_cast<std::stringstream*>(inputStream_)) {
			return ss_ptr->str();
		}
#endif

		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) ctx->SetException("str() method is primarily for iostreams created as string streams or those wrapping an external std::stringstream (if RTTI enabled).");
		return "";
	}

	void str(const string& s) {
		if (isProperStringStream_) {
			internalStringStream_.str(s);
			internalStringStream_.clear();
			internalStringStream_.seekg(0);
			internalStringStream_.seekp(0);
		}
		else {
			asIScriptContext* ctx = asGetActiveContext();
			if (ctx) ctx->SetException("str(string) method is only for iostreams created as string streams.");
		}
	}

private:
	mutable int ref_;
	std::stringstream internalStringStream_;
	bool isProperStringStream_;
	bool isStatic_;
};


// --- Generic operator wrappers ---
void WriteGeneric(asIScriptGeneric* gen) {
	CScriptIOStream* streamObj = static_cast<CScriptIOStream*>(gen->GetObject());
	if (!streamObj || !streamObj->outputStream_) {
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) ctx->SetException("Attempt to write via opShl to a null stream object or null output stream.");
		if (streamObj) gen->SetReturnObject(streamObj);
		return;
	}

	void* valuePtr = gen->GetArgAddress(0);
	int typeId = gen->GetArgTypeId(0);
	std::ostream& ostr = *(streamObj->outputStream_);

	if (typeId == asTYPEID_BOOL) ostr << *static_cast<const bool*>(valuePtr);
	else if (typeId == asTYPEID_INT8) ostr << static_cast<int32_t>(*static_cast<const int8_t*>(valuePtr));
	else if (typeId == asTYPEID_UINT8) ostr << static_cast<uint32_t>(*static_cast<const uint8_t*>(valuePtr));
	else if (typeId == asTYPEID_INT16) ostr << *static_cast<const int16_t*>(valuePtr);
	else if (typeId == asTYPEID_UINT16) ostr << *static_cast<const uint16_t*>(valuePtr);
	else if (typeId == asTYPEID_INT32) ostr << *static_cast<const int32_t*>(valuePtr);
	else if (typeId == asTYPEID_UINT32) ostr << *static_cast<const uint32_t*>(valuePtr);
	else if (typeId == asTYPEID_INT64) ostr << *static_cast<const int64_t*>(valuePtr);
	else if (typeId == asTYPEID_UINT64) ostr << *static_cast<const uint64_t*>(valuePtr);
	else if (typeId == asTYPEID_FLOAT) ostr << *static_cast<const float*>(valuePtr);
	else if (typeId == asTYPEID_DOUBLE) ostr << *static_cast<const double*>(valuePtr);
	else if (typeId == g_stringTypeId) ostr << *static_cast<const string*>(valuePtr);
	else {
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) {
			asITypeInfo* typeInfo = gen->GetEngine()->GetTypeInfoById(typeId);
			string msg = "iostream::opShl cannot write type '";
			msg += typeInfo ? typeInfo->GetName() : "unknown";
			msg += "'.";
			ctx->SetException(msg.c_str());
		}
	}
	gen->SetReturnObject(streamObj);
}

void ReadGeneric(asIScriptGeneric* gen) {
	CScriptIOStream* streamObj = static_cast<CScriptIOStream*>(gen->GetObject());
	if (!streamObj || !streamObj->inputStream_) {
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) ctx->SetException("Attempt to read via opShr from a null stream object or null input stream.");
		if (streamObj) gen->SetReturnObject(streamObj);
		return;
	}

	void* valuePtr = gen->GetArgAddress(0);
	int typeId = gen->GetArgTypeId(0);
	std::istream& istr = *(streamObj->inputStream_);

	if (typeId == asTYPEID_BOOL) istr >> *static_cast<bool*>(valuePtr);
	else if (typeId == asTYPEID_INT8) { int16_t temp; istr >> temp; *static_cast<int8_t*>(valuePtr) = static_cast<int8_t>(temp); }
	else if (typeId == asTYPEID_UINT8) { uint16_t temp; istr >> temp; *static_cast<uint8_t*>(valuePtr) = static_cast<uint8_t>(temp); }
	else if (typeId == asTYPEID_INT16) istr >> *static_cast<int16_t*>(valuePtr);
	else if (typeId == asTYPEID_UINT16) istr >> *static_cast<uint16_t*>(valuePtr);
	else if (typeId == asTYPEID_INT32) istr >> *static_cast<int32_t*>(valuePtr);
	else if (typeId == asTYPEID_UINT32) istr >> *static_cast<uint32_t*>(valuePtr);
	else if (typeId == asTYPEID_INT64) istr >> *static_cast<int64_t*>(valuePtr);
	else if (typeId == asTYPEID_UINT64) istr >> *static_cast<uint64_t*>(valuePtr);
	else if (typeId == asTYPEID_FLOAT) istr >> *static_cast<float*>(valuePtr);
	else if (typeId == asTYPEID_DOUBLE) istr >> *static_cast<double*>(valuePtr);
	else if (typeId == g_stringTypeId) istr >> *static_cast<string*>(valuePtr);
	else {
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx) {
			asITypeInfo* typeInfo = gen->GetEngine()->GetTypeInfoById(typeId);
			string msg = "iostream::opShr cannot read type '";
			msg += typeInfo ? typeInfo->GetName() : "unknown";
			msg += "'.";
			ctx->SetException(msg.c_str());
		}
	}
	gen->SetReturnObject(streamObj);
}


// --- Factories and Global Accessors ---
CScriptIOStream* StringStreamFactory() {
	return new CScriptIOStream();
}

static CScriptIOStream g_script_cout(&std::cout, nullptr, true);
static CScriptIOStream g_script_cin(nullptr, &std::cin, true);
static CScriptIOStream g_script_cerr(&std::cerr, nullptr, true);

CScriptIOStream* get_cout_global() {
	g_script_cout.AddRef();
	return &g_script_cout;
}

CScriptIOStream* get_cin_global() {
	g_script_cin.AddRef();
	return &g_script_cin;
}

CScriptIOStream* get_cerr_global() {
	g_script_cerr.AddRef();
	return &g_script_cerr;
}


// --- Registration Function ---
void RegisterScriptIOStreams(asIScriptEngine* engine) {
	int r;

	g_stringTypeId = engine->GetTypeIdByDecl("string");
	if (g_stringTypeId < 0) {
		assert(g_stringTypeId >= 0 && "std::string not registered with AngelScript before iostream");
		return;
	}

	r = engine->RegisterGlobalProperty("const int IOSTREAM_EOF", (void*)&SCRIPT_EOF_VALUE); assert(r >= 0);

	r = engine->RegisterObjectType("iostream", 0, asOBJ_REF); assert(r >= 0);

	r = engine->RegisterObjectBehaviour("iostream", asBEHAVE_FACTORY, "iostream@ f()", asFUNCTION(StringStreamFactory), asCALL_CDECL); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("iostream", asBEHAVE_ADDREF, "void f()", asMETHOD(CScriptIOStream, AddRef), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectBehaviour("iostream", asBEHAVE_RELEASE, "void f()", asMETHOD(CScriptIOStream, Release), asCALL_THISCALL); assert(r >= 0);

	// Output methods
	r = engine->RegisterObjectMethod("iostream", "void write(const string &in)", asMETHOD(CScriptIOStream, write), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "void put(int8)", asMETHOD(CScriptIOStream, put), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "void flush()", asMETHOD(CScriptIOStream, flush), asCALL_THISCALL); assert(r >= 0);

	// Input methods
	r = engine->RegisterObjectMethod("iostream", "string read()", asMETHOD(CScriptIOStream, read), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "string getline()", asMETHOD(CScriptIOStream, getline), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "int get()", asMETHOD(CScriptIOStream, get), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "int peek()", asMETHOD(CScriptIOStream, peek), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "void ignore(uint count = 1, int delim = IOSTREAM_EOF)", asMETHOD(CScriptIOStream, ignore), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "void unget()", asMETHOD(CScriptIOStream, unget), asCALL_THISCALL); assert(r >= 0);

	// State methods
	r = engine->RegisterObjectMethod("iostream", "bool good() const", asMETHOD(CScriptIOStream, good), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "bool eof() const", asMETHOD(CScriptIOStream, eof), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "bool fail() const", asMETHOD(CScriptIOStream, fail), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "bool bad() const", asMETHOD(CScriptIOStream, bad), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "void clear_flags()", asMETHOD(CScriptIOStream, clear_flags), asCALL_THISCALL); assert(r >= 0);

	// Seeking methods
	r = engine->RegisterObjectMethod("iostream", "void seekg(uint)", asMETHOD(CScriptIOStream, seekg), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "uint tellg()", asMETHOD(CScriptIOStream, tellg), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "void seekp(uint)", asMETHOD(CScriptIOStream, seekp), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "uint tellp()", asMETHOD(CScriptIOStream, tellp), asCALL_THISCALL); assert(r >= 0);

	// StringStream specific methods
	r = engine->RegisterObjectMethod("iostream", "string str()", asMETHODPR(CScriptIOStream, str, (void), string), asCALL_THISCALL); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "void str(const string &in)", asMETHODPR(CScriptIOStream, str, (const string&), void), asCALL_THISCALL); assert(r >= 0);

	// Generic stream operators
	r = engine->RegisterObjectMethod("iostream", "iostream& opShl(const ?&in)", asFUNCTION(WriteGeneric), asCALL_GENERIC); assert(r >= 0);
	r = engine->RegisterObjectMethod("iostream", "iostream& opShr(?&out)", asFUNCTION(ReadGeneric), asCALL_GENERIC); assert(r >= 0);

	// Global stream accessors
	r = engine->RegisterGlobalFunction("iostream@ get_cout() property", asFUNCTION(get_cout_global), asCALL_CDECL); assert(r >= 0);
	r = engine->RegisterGlobalFunction("iostream@ get_cin() property", asFUNCTION(get_cin_global), asCALL_CDECL); assert(r >= 0);
	r = engine->RegisterGlobalFunction("iostream@ get_cerr() property", asFUNCTION(get_cerr_global), asCALL_CDECL); assert(r >= 0);
}
