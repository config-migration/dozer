lexer grammar StraceLexer;


// Fragments (not tokens, but useful for building tokens)

fragment DIGIT : ('0'..'9') ;
fragment I04 : ('0'..'4') ;
fragment I05 : ('0'..'5') ;
fragment I12 : ('1'..'2') ;
fragment I19 : ('1'..'9') ;
fragment HEX_DIGIT : DIGIT | ('a'..'f') ;
fragment IPV4_OCTET
    : DIGIT
    | I19 DIGIT
    | '1' DIGIT DIGIT
    | '2' I04 DIGIT
    | '25' I05
    ;
fragment IPV6_HEXTET : HEX_DIGIT (HEX_DIGIT (HEX_DIGIT (HEX_DIGIT)?)?)? ;
fragment LETTER : ('a'..'z') | ('A'..'Z') ;
fragment AMPERSAND : '&' ;
fragment UNDERSCORE : '_' ;


// Tokens

WHITESPACE : ('\t' | ' ' | '\u000C')+ -> channel(HIDDEN) ;
OMITTED_ARGUMENTS : '/* ' NUMBER ' entries */' ;
COMMENT : '/*' .*? '*/' -> skip ;

NEWLINE : '\r'? '\n' ;

RESUMED_START : '<... ' ;
RESUMED_END : ' resumed>' ;
UNFINISHED : '<unfinished ...>' ;
RESUME_INTERRUPTED_FUTEX : '<... resuming interrupted futex ...>' -> skip ;
SIGNAL_DELIMITER : '---' ;
EXIT_DELIMITER : '+++' ;
EXITED_WITH : 'exited with' ;
KILLED_BY : 'killed by' ;
TRUNCATED : 'TRUNCATED' ;

LEFT_PARENTHESIS : '(' ;
RIGHT_PARENTHESIS : ')' ;
EQUALS : '=' ;
COMMA : ',' ;
QUESTION_MARK : '?' ;
TILDE : '~' ;
LEFT_BRACKET : '[' ;
RIGHT_BRACKET : ']' ;
LEFT_CURLY_BRACKET : '{' ;
RIGHT_CURLY_BRACKET : '}' ;
FD_LEFT_ANGLE_BRACKET : '<' -> pushMode(MODE_FD) ;
COLON : ':' ;
SINGLE_ARROW : '->' ;
DOUBLE_ARROW : '=>' ;
NULL : 'NULL' ;
NUMBER
    : '0' DIGIT+
    | '0x' (DIGIT | 'a'..'f' )+
    | '-'? DIGIT+
    ;
BOOLEAN_BINARY_OPERATOR : '&&' | '||' | '==' ;
NUMERIC_BINARY_OPERATOR : '&' | '|' | '*' | '/' | '+' | '-' ;
ELLIPSIS : '...' ;

IDENTIFIER
    : (LETTER | UNDERSCORE) (LETTER | UNDERSCORE | DIGIT)*
    | AMPERSAND (LETTER | UNDERSCORE | DIGIT)+
    ;
STRING : '"' (('\\\\' | '\\"') | .)*? '"' ELLIPSIS?;


mode MODE_FD;
FD_WHITESPACE : ('\t' | ' ' | '\u000C')+ -> channel(HIDDEN) ;
DEV_LEFT_ANGLE_BRACKET : '<' -> pushMode(MODE_DEV) ;
FD_RIGHT_ANGLE_BRACKET : '>' -> popMode ;
FD_INFO_OPEN : ':[' -> pushMode(MODE_FD_INFO) ;
FD_SOCKET_PROTOCOL
    : 'UNIX'
    | 'TCP'
    | 'TCPv6'
    | 'UDP'
    | 'UDPv6'
    | 'UDPLITE'
    | 'UDPLITEv6'
    | 'DCCP'
    | 'DCCPv6'
    | 'SCTP'
    | 'SCTPv6'
    | 'L2TP/IP'
    | 'L2TP/IPv6'
    | 'PING'
    | 'PINGv6'
    | 'RAW'
    | 'RAWv6'
    ;
FD_SOCKET_PROTOCOL_NETLINK : 'NETLINK' ; // Netlink is special
// A single character wildcard. Must be specified last. Will be matched as a
// last resort if nothing else can be.
FD_CHARACTER : . ;


mode MODE_DEV;
DEV_WHITESPACE : ('\t' | ' ' | '\u000C')+ -> channel(HIDDEN) ;
DEV_RIGHT_ANGLE_BRACKET : '>' -> popMode ;
DEV_COLON : ':' ;
DEV_NUMBER : DIGIT+ ;
DEV_TEXT : ~[ 0-9>]+ ;


mode MODE_FD_INFO;
FD_INFO_LEFT_BRACKET : '[' -> pushMode(MODE_FD_INFO) ; // Needed for IPV6 addresses with ports.
FD_INFO_RIGHT_BRACKET : ']' -> popMode ;
FD_INFO_COLON : ':' ;
FD_INFO_COMMA : ',' ;
FD_INFO_REFERENCE : '->' ;
FD_INFO_NUMBER : DIGIT+ ;
FD_INFO_IPV4 : IPV4_OCTET '.' IPV4_OCTET '.' IPV4_OCTET '.' IPV4_OCTET (FD_INFO_COLON FD_INFO_NUMBER)?;
FD_INFO_IPV6
    : FD_INFO_LEFT_BRACKET FD_INFO_IPV6_ADDR FD_INFO_RIGHT_BRACKET FD_INFO_COLON FD_INFO_NUMBER
    | FD_INFO_IPV6_ADDR
    ;
FD_INFO_IPV6_ADDR
    : FD_INFO_COLON FD_INFO_COLON
    | IPV6_HEXTET (FD_INFO_COLON FD_INFO_COLON? IPV6_HEXTET)*
    ;
FD_INFO_NETLINK_PROTOCOL : [A-Z0-9]+ ;
FD_INFO_FILENAME : '"' (('\\\\' | '\\"') | .)*? '"';
