#include "Persistence.h"

#include "Bytes.h"

using namespace RNS;

// ArduinoJson 7: JsonDocument is auto-sized, no capacity argument needed.
/*static*/ JsonDocument _document;
/*static*/ Bytes _buffer(Type::Persistence::BUFFER_MAXSIZE);
