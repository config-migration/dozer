parser grammar StraceParser;


options { tokenVocab=StraceLexer; }


// Production Rules


// Strace
strace
    : NEWLINE* trace_line* TRUNCATED? NEWLINE*
    ;
trace_line
    : NUMBER? (syscall | signal | exit_statement) NEWLINE
    ;


// Syscall
syscall
    : syscall_start syscall_arguments? syscall_end
    | syscall_start syscall_arguments? syscall_unfinished
    | syscall_resumed mapping? syscall_arguments? syscall_end
    ;
syscall_start
    : IDENTIFIER LEFT_PARENTHESIS
    ;
syscall_arguments
    : syscall_argument (COMMA syscall_argument)* (COMMA ELLIPSIS)?
    ;
syscall_argument
    : literal
    | OMITTED_ARGUMENTS
    ;
syscall_end
    : RIGHT_PARENTHESIS EQUALS return_value
    ;
syscall_resumed
    : RESUMED_START IDENTIFIER RESUMED_END COMMA?
    ;
syscall_unfinished
    : COMMA? UNFINISHED
    ;


// Signal
signal
    : SIGNAL_DELIMITER IDENTIFIER collection SIGNAL_DELIMITER
    ;


// Exit statement
exit_statement
    : EXIT_DELIMITER EXITED_WITH NUMBER EXIT_DELIMITER
    | EXIT_DELIMITER KILLED_BY IDENTIFIER EXIT_DELIMITER
    ;



// Literals
literal
    : (IDENTIFIER EQUALS)? literal_value mapping?
    | mapping
    ;
literal_value
    : collection
    | file_descriptor
    | function_call
    | numeric_expression
    | boolean_expression
    | NULL
    | NUMBER
    | STRING
    | IDENTIFIER
    ;
mapping
    : DOUBLE_ARROW literal
    ;
literal_list
    : literal ((COMMA | SINGLE_ARROW)? literal)* (COMMA? ELLIPSIS)?
    ;
collection // Lits/vectors, sets, structs, etc.
    : TILDE? LEFT_BRACKET literal_list? RIGHT_BRACKET
    | TILDE? LEFT_PARENTHESIS literal_list? RIGHT_PARENTHESIS
    | LEFT_CURLY_BRACKET literal_list? RIGHT_CURLY_BRACKET
    ;
file_descriptor
    : NUMBER FD_LEFT_ANGLE_BRACKET FD_CHARACTER+ FD_RIGHT_ANGLE_BRACKET
    | NUMBER FD_LEFT_ANGLE_BRACKET FD_CHARACTER+ device_info FD_RIGHT_ANGLE_BRACKET
    | NUMBER FD_LEFT_ANGLE_BRACKET FD_SOCKET_PROTOCOL (inode_info | ip_info) FD_RIGHT_ANGLE_BRACKET
    | NUMBER FD_LEFT_ANGLE_BRACKET FD_SOCKET_PROTOCOL_NETLINK (inode_info | netlink_info) FD_RIGHT_ANGLE_BRACKET
    | NUMBER FD_LEFT_ANGLE_BRACKET FD_CHARACTER+ inode_info FD_RIGHT_ANGLE_BRACKET
    ;
device_info
    : DEV_LEFT_ANGLE_BRACKET DEV_TEXT DEV_NUMBER DEV_COLON DEV_NUMBER DEV_RIGHT_ANGLE_BRACKET
    ;
inode_info
    : FD_INFO_OPEN FD_INFO_NUMBER (FD_INFO_REFERENCE FD_INFO_NUMBER)? (FD_INFO_COMMA FD_INFO_FILENAME)? FD_INFO_RIGHT_BRACKET
    ;
ip_info
    : FD_INFO_OPEN ip_addr (FD_INFO_REFERENCE ip_addr)? FD_INFO_RIGHT_BRACKET
    ;
ip_addr
    : FD_INFO_IPV4
    | FD_INFO_IPV6
    ;
netlink_info
    : FD_INFO_OPEN FD_INFO_NETLINK_PROTOCOL FD_INFO_COLON FD_INFO_NUMBER FD_INFO_RIGHT_BRACKET
    ;
function_call
    : IDENTIFIER LEFT_PARENTHESIS literal_list RIGHT_PARENTHESIS
    ;
numeric_expression
    : (NUMBER | IDENTIFIER) (NUMERIC_BINARY_OPERATOR (NUMBER | IDENTIFIER))+
    ;
boolean_expression
    : LEFT_BRACKET LEFT_CURLY_BRACKET literal (BOOLEAN_BINARY_OPERATOR literal)+ RIGHT_CURLY_BRACKET RIGHT_BRACKET
    ;
return_value
    : (NUMBER | QUESTION_MARK | file_descriptor) return_notes?
    ;
return_notes
    : ~NEWLINE+?
    ;
