/*
    Language mode for CodeMirror (https://codemirror.net/)
*/

CodeMirror.defineMode("yara", function(config) {
    function words(str) {
      var obj = {}, words = str.split(" ");
      for (var i = 0; i < words.length; ++i) obj[words[i]] = true;
      return obj;
    }
    var keywords = words("all and any ascii at condition contains entrypoint filesize for " +
                         "fullword global import in include int16 int32 int8 matches meta " +
                         "nocase not of or private rule strings them uint16 uint32 " +
                         "uint8 wide xor");

    var atoms = {"true": true, "false": true};

    var isOperatorChar = /[+\-*&%=<>!?|\/]/;

    function tokenBase(stream, state) {
      var ch = stream.next();
      if (ch == "#" && state.startOfLine) {
        stream.skipToEnd();
        return "meta";
      }
      if (/[\[\]{}\(\),;\:\.]/.test(ch)) {
        return null
      }
      if (/\d/.test(ch)) {
        stream.eatWhile(/[\w\.]/);
        return "number";
      }
      if (ch == "/") {
        if (stream.eat("/")) {
          stream.skipToEnd();
          return "comment";
        }
        if (stream.eat("*")) {
          state.tokenize = tokenComment;
          return tokenComment(stream, state);
        }
      }
      if (ch == '"' || ch == '/') {
        state.tokenize = tokenString(ch);
        return state.tokenize(stream, state);
      }
      if (isOperatorChar.test(ch)) {
        stream.eatWhile(isOperatorChar);
        return "operator";
      }
      stream.eatWhile(/[\w\$_]/);
      var cur = stream.current();
      if (keywords.propertyIsEnumerable(cur)) return "keyword";
      if (atoms.propertyIsEnumerable(cur)) return "atom";
      return "word";
    }

    function tokenString(quote) {
      return function(stream, state) {
        var escaped = false, next, end = false;
        while ((next = stream.next()) != null) {
          if (next == quote && !escaped) {end = true; break;}
          escaped = !escaped && next == "\\";
        }
        if (end || !escaped) state.tokenize = null;
        return "string";
      };
    }

    function tokenComment(stream, state) {
      var maybeEnd = false, ch;
      while (ch = stream.next()) {
        if (ch == "/" && maybeEnd) {
          state.tokenize = null;
          break;
        }
        maybeEnd = (ch == "*");
      }
      return "comment";
    }

    // Interface

    return {
      startState: function(basecolumn) {
        return {tokenize: null};
      },

      token: function(stream, state) {
        if (stream.eatSpace()) return null;
        var style = (state.tokenize || tokenBase)(stream, state);
        return style;
      },

      electricChars: "{}"
    };
});

CodeMirror.defineMIME("text/yara", "yara");
CodeMirror.defineMIME("text/x-yara", "yara");
