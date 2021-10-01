"""Strace Parser."""


# Imports
from pathlib import Path
from typing import List, Optional, Tuple, Union

from antlr4 import (
    BailErrorStrategy, CommonTokenStream, FileStream, InputStream
)
from antlr4 import Recognizer
from antlr4.error.Errors import CancellationException
from antlr4.error.ErrorListener import ErrorListener
from antlr4.error.ErrorStrategy import (
    ParseCancellationException, RecognitionException, NoViableAltException
)
from antlr4.Parser import ParserRuleContext
from antlr4.tree.Tree import Tree
from antlr4.Token import CommonToken

from lib.antlr_generated.strace.StraceLexer import StraceLexer
from lib.antlr_generated.strace.StraceParser import StraceParser
from lib.antlr_generated.strace.StraceParserVisitor import StraceParserVisitor

from lib import logger
from lib.strace import classes
from lib.strace.classes import Strace


# Types
LIST_TREE = List[Union[str, 'LIST_TREE']]


def _token_str(t: CommonToken) -> str:
    """Convert a token to a string.
    
    Helper function for creating a string from a token that includes the 
    symbolic type name instead of the integer type.
    
    Parameters
    ----------
    t : CommonToken
        Token to convert to string.

    Returns
    -------
    str
        String representation of the token.
    """
    token_type = t.type
    t.type = StraceLexer.symbolicNames[t.type]
    token_str = str(t)
    t.type = token_type
    return token_str


class BailErrorListener(ErrorListener):
    """Lexer error listener that bails on error."""

    def syntaxError(self,
                    recognizer: Recognizer,
                    offendingSymbol: Optional[CommonToken],
                    line: int,
                    column: int,
                    msg: str,
                    e: RecognitionException):
        """Handle a syntax error.

        Parameters
        ----------
        recognizer : Recognizer
            Recognizer that encountered the recognition exception.
        offendingSymbol : Optional[CommonToken]
            Symbol that caused the syntax error.
        line : int
            Error line number.
        column : int
            Column line number.
        msg : str
            Error message.
        e : RecognitionException
            Original recognition exception.

        Raises
        ------
        LexCancellationException
            Raised to cancel lexing.
        """
        raise LexCancellationException(
            recognizer=recognizer,
            offendingSymbol=offendingSymbol,
            line=line,
            column=column,
            msg=msg,
            e=e,
        )


class LexCancellationException(CancellationException):
    """Cancellation exception related to lexing."""

    def __init__(self,
                 recognizer: Recognizer,
                 offendingSymbol: Optional[CommonToken],
                 line: int,
                 column: int,
                 msg: str,
                 e: RecognitionException):
        """Create a new lex cancellation exception.

        Parameters
        ----------
        recognizer : Recognizer
            Recognizer that encountered the recognition exception.
        offendingSymbol : Optional[CommonToken]
            Symbol that caused the syntax error.
        line : int
            Error line number.
        column : int
            Column line number.
        msg : str
            Error message.
        e : RecognitionException
            Original recognition exception.
        """
        super().__init__(msg)
        self.args = (e, *self.args)
        self.recognizer = recognizer
        self.offendingSymbol = offendingSymbol
        self.line = line
        self.column = column


def _parse_number(num: str) -> int:
    """Parse a number literal as an int.

    Parameters
    ----------
    num : str
        String valued number literal.

    Raises
    ------
    Exception
        Raised if num is not a non-empty string.
    TypeError
        Raised if num cannot be parsed as an integer.

    Returns
    -------
    int
        Equivalent integer value.
    """
    # Validate num
    if not isinstance(num, str) or not num:
        raise Exception('Number must be a non-empty string.')

    # Get correct base
    if num[:2] == '0x':
        base = 16
    elif num[0] == '0':
        base = 8
    else:
        base = 10

    # Parse
    return int(num, base)


def _parse_input_stream(stream: InputStream, **kwargs) -> Strace:
    """Parse an strace using a specific input stream.

    Parameters
    ----------
    stream : InputStream
        Strace input stream.
    **kwargs
        Additional strace attributes that should be set.

    Returns
    -------
    Strace
        Parsed strace representation.
    """
    # Create lexer and token stream
    lexer = StraceLexer(stream)
    lexer.removeErrorListeners()
    lexer.addErrorListener(BailErrorListener())

    # Create token stream
    token_stream = CommonTokenStream(lexer)

    # Create Antlr parser and set error handler
    parser = StraceParser(token_stream)
    parser._errHandler = BailErrorStrategy()

    # Parse the token stream for an strace context and visit the tree.
    try:

        strace = StraceVisitorImpl().visit(parser.strace())

    except ParseCancellationException as e:

        # Get the root cause of the cancellation
        cause = e.args[0]

        if isinstance(cause, NoViableAltException):
            tokens = '\n            '.join(
                _token_str(token)
                for token in token_stream.getTokens(
                    cause.startToken.tokenIndex,
                    cause.offendingToken.tokenIndex + 1
                )
            )
            expected = [
                StraceLexer.symbolicNames[i]
                for i in cause.getExpectedTokens()
            ]
            logger.error(
                f'\n'
                f'    No Viable Alternative.\n'
                f'    Tokens: {tokens}.\n'
                f'    Expected Tokens: {expected}.'
            )
        elif isinstance(cause, RecognitionException):
            offending = _token_str(cause.offendingToken)
            expected = [
                StraceLexer.symbolicNames[i]
                for i in cause.getExpectedTokens()
            ]
            logger.error(
                f'\n'
                f'    Recognition Exception.\n'
                f'    Offending Token: {offending}.\n'
                f'    Expected Tokens: {expected}.'
            )
        else:
            logger.exception('Unknown exception encountered during parsing.')

        raise

    except LexCancellationException as e:

        # Get root cause
        cause = e.args[0]

        # Recent tokens under consideration
        tokens = []

        # Get previous tokens
        total_previous_tokens = min(5, token_stream.index)
        idx = total_previous_tokens
        while len(tokens) < total_previous_tokens:
            token = token_stream.LB(idx)
            if token:
                tokens.append(token)
            idx -= 1

        # Get next tokens
        idx = 1
        while True:
            try:
                token = token_stream.LT(idx)
                if token and token.stop < cause.startIndex:
                    tokens.append(token)
                    idx += 1
                else:
                    break
            except LexCancellationException:
                break

        # Convert to token string
        tokens = '\n            '.join(map(_token_str, tokens))

        # Log and reraise
        logger.error(
            f'\n'
            f'    Recognition Exception at {e.line}:{e.column}\n'
            f'    {e.args[-1]}\n'
            f'    Current Mode: {lexer.modeNames[lexer._mode]}\n'
            f'    Tokens: {tokens}'
        )
        raise

    # Set additional attributes
    for k, v in kwargs.items():
        if hasattr(strace, k):
            setattr(strace, k, v)

    # Return formatted strace
    return strace


def _tree(o: Tree) -> LIST_TREE:
    """Convert a context tree into a list tree.

    Parameters
    ----------
    o : Tree
        Antlr tree object.

    Returns
    -------
    LIST_TREE
        List of node strings.
    """
    if isinstance(o, ParserRuleContext):
        return [_tree(c) for c in o.children]
    else:
        return o.getText()


def parse(path: Path, **kwargs) -> Strace:
    """Parse an strace output file.

    Parameters
    ----------
    path : Path
        Path to strace file.

    Returns
    -------
    Strace
        Parsed strace representation.
    """
    return _parse_input_stream(FileStream(str(path)), **kwargs)


def parse_string(string: str, **kwargs) -> Strace:
    """Parse an strace string.

    Parameters
    ----------
    string : str
        String containing strace output.

    Returns
    -------
    Strace
        Parsed strace representation.
    """
    return _parse_input_stream(InputStream(string), **kwargs)


class StraceVisitorImpl(StraceParserVisitor):
    """Strace visitor."""

    def visitStrace(self, ctx: StraceParser.StraceContext) -> classes.Strace:
        """Visit an strace context.

        Parameters
        ----------
        ctx : StraceParser.StraceContext
            Strace context object from the parse tree.

        Returns
        -------
        Strace
            Strace object parsed from ctx.
        """
        return classes.Strace(
            trace_lines=list(map(self.visit, ctx.trace_line())),
            truncated=bool(ctx.TRUNCATED())
        )

    def visitTrace_line(self,
                        ctx: StraceParser.Trace_lineContext
                        ) -> classes.TraceLine:
        """Visit a traceline context.

        Parameters
        ----------
        ctx : StraceParser.Trace_lineContext
            Traceline context object from the parse tree.

        Returns
        -------
        TraceLine
            Traceline object parsed from ctx.
        """
        # Construct proper traceline subtype
        if ctx.syscall():
            trace_line = self.visitSyscall(ctx.syscall())
        elif ctx.signal():
            trace_line = self.visitSignal(ctx.signal())
        elif ctx.exit_statement():
            trace_line = self.visitExit_statement(ctx.exit_statement())
        else:
            raise Exception('Unknown traceline type.')

        # Set process identifier
        if ctx.NUMBER():
            trace_line.pid = _parse_number(ctx.NUMBER().getText())

        return trace_line

    def visitSyscall(self,
                     ctx: StraceParser.SyscallContext) -> classes.Syscall:
        """Visit a syscall context.

        Parameters
        ----------
        ctx : StraceParser.SyscallContext
            Syscall context object from the parse tree.

        Returns
        -------
        Syscall
            Syscall object parsed from ctx.
        """
        # Determine if the syscall is unfinished or resumed
        unfinished = ctx.syscall_unfinished()
        resumed = ctx.syscall_resumed()

        # Common args
        kwargs = {
            'unfinished': bool(unfinished),
            'resumed': bool(resumed),
        }

        # Get syscall name
        if not resumed:
            kwargs['name'] = ctx.syscall_start().IDENTIFIER().getText()
        else:
            kwargs['name'] = resumed.IDENTIFIER().getText()

        # Get syscall arguments
        kwargs['arguments'] = []
        if ctx.mapping():
            destination = self.visit(ctx.mapping())
            kwargs['arguments'].append(classes.Mapping(None, destination))
        if ctx.syscall_arguments():
            kwargs['arguments'] += self.visit(ctx.syscall_arguments())

        # Get exit code and notes
        if not unfinished:
            return_value = ctx.syscall_end().return_value()
            if return_value.NUMBER():
                kwargs['exit_code'] = _parse_number(
                    return_value.NUMBER().getText()
                )
            elif return_value.QUESTION_MARK():
                kwargs['exit_code'] = return_value.QUESTION_MARK().getText()

            return_notes = return_value.return_notes()
            if return_notes:
                exit_notes = self.visit(return_notes)
                kwargs['exit_nodes'] = exit_notes

        return classes.Syscall(**kwargs)

    def visitSyscall_arguments(self,
                               ctx: StraceParser.Syscall_argumentsContext
                               ) -> List[Union[
                                   classes.Literal,
                                   classes.OmittedArguments
                               ]]:
        """Visit a syscall arguments context.

        Parameters
        ----------
        ctx : StraceParser.Syscall_argumentsContext
            Syscall arguments context object from the parse tree.

        Returns
        -------
        list[classes.SyscallArgument]
            List of arguments parsed from ctx.
        """
        return list(map(self.visit, ctx.syscall_argument()))

    def visitSyscall_argument(self, ctx: StraceParser.Syscall_argumentContext
                              ) -> Union[
                                  classes.OmittedArguments,
                                  classes.Literal
                              ]:
        """Visit a syscall argument context.

        Parameters
        ----------
        ctx : StraceParser.Syscall_argumentContext
            Syscall argument context object from the parse tree.

        Returns
        -------
        classes.SyscallArgument
            Argument parsed from ctx.
        """
        # If omitted, return omitted arguments.
        if ctx.OMITTED_ARGUMENTS():
            return classes.OmittedArguments()
        else:
            return self.visit(ctx.literal())

    def visitLiteral(self, ctx: StraceParser.LiteralContext
                     ) -> Union[classes.Literal, classes.Mapping]:
        """Visit a literal context.

        Parameters
        ----------
        ctx : StraceParser.LiteralContext
            Literal context object from the parse tree.

        Returns
        -------
        Union[classes.Literal, classes.Mapping]
            Literal value parsed from ctx.
        """
        # Get identifier
        if ctx.IDENTIFIER():
            identifier = classes.Identifier(ctx.IDENTIFIER().getText())
        else:
            identifier = None

        # Create literal
        literal = classes.Literal(
            self.visit(ctx.literal_value()),
            identifier=identifier
        )

        # Return literal or a mapping
        if ctx.mapping():
            mapped = self.visit(ctx.mapping())
            return classes.Mapping(literal, mapped)
        else:
            return literal

    def visitLiteral_value(self, ctx: StraceParser.Literal_valueContext
                           ) -> classes.LiteralValue:
        """Visit a literal context.

        Parameters
        ----------
        ctx : StraceParser.Literal_valueContext
            Literal context object from the parse tree.

        Returns
        -------
        classes.LiteralValue
            Literal value parsed from ctx.
        """
        # Return the correct type of value.
        if ctx.NULL():
            return classes.NullLiteral(ctx.NULL().getText())
        elif ctx.NUMBER():
            return classes.NumberLiteral(_parse_number(ctx.NUMBER().getText()))
        elif ctx.STRING():
            s = ctx.STRING().getText().rstrip('.')[1:-1]
            return classes.StringLiteral(s)
        elif ctx.IDENTIFIER():
            return classes.Identifier(ctx.IDENTIFIER().getText())
        else:
            return self.visit(
                ctx.collection()
                or ctx.file_descriptor()
                or ctx.function_call()
                or ctx.numeric_expression()
                or ctx.boolean_expression()
            )

    def visitMapping(self,
                     ctx: StraceParser.MappingContext) -> classes.Literal:
        """Visit a mapping context.

        Parameters
        ----------
        ctx : StraceParser.MappingContext
            Mapping context from the parse tree.

        Returns
        -------
        classes.Literal
            Mapped literal parsed from ctx.
        """
        return self.visit(ctx.literal())

    def visitLiteral_list(self,
                          ctx: StraceParser.Literal_listContext
                          ) -> List[classes.LiteralValue]:
        """Visit a literal list context.

        Parameters
        ----------
        ctx : StraceParser.Literal_listContext
            Literal list context from the parse tree.

        Returns
        -------
        list[classes.LiteralValue]
            List of values parsed from ctx.
        """
        return list(map(self.visit, ctx.literal()))

    def visitCollection(self, ctx: StraceParser.CollectionContext
                        ) -> classes.Collection:
        """Visit a collection context.

        Parameters
        ----------
        ctx : StraceParser.CollectionContext
            Collection context.

        Returns
        -------
        classes.Collection
            Parsed collection.
        """
        if ctx.literal_list():
            items = self.visit(ctx.literal_list())
        else:
            items = []

        return classes.Collection(items)

    def visitFile_descriptor(self,
                             ctx: StraceParser.File_descriptorContext
                             ) -> classes.FileDescriptor:
        """Visit a file descriptor context.

        Parameters
        ----------
        ctx : StraceParser.File_descriptorContext

        Returns
        -------
        classes.FileDescriptor
            File descriptor from ctx.
        """
        # Parse file descriptor number
        number = _parse_number(ctx.NUMBER().getText())

        # Return correct type of file descriptor
        if ctx.device_info():
            path = ''.join(map(lambda c: c.getText(), ctx.FD_CHARACTER()))
            dev_ctx = ctx.device_info()
            return classes.DeviceFileDescriptor(
                number=number,
                path=path,
                device_type=dev_ctx.DEV_TEXT().getText(),
                major=_parse_number(dev_ctx.DEV_NUMBER(0).getText()),
                minor=_parse_number(dev_ctx.DEV_NUMBER(1).getText())
            )
        elif ctx.FD_SOCKET_PROTOCOL() and ctx.inode_info():
            inode, reference, bind = self.visitInode_info(ctx.inode_info())
            return classes.InodeFileDescriptor(
                number=number,
                protocol=ctx.FD_SOCKET_PROTOCOL().getText(),
                inode=inode,
                reference=reference,
                bind=bind,
            )
        elif ctx.FD_SOCKET_PROTOCOL() and ctx.ip_info():
            ip_addr_ctxs = ctx.ip_info().ip_addr()

            if len(ip_addr_ctxs) == 1:
                source = None
                d_ctx = ip_addr_ctxs[0]
                node = d_ctx.FD_INFO_IPV4() or d_ctx.FD_INFO_IPV6()
                destination = node.getText()
            else:
                s_ctx = ip_addr_ctxs[0]
                s_node = s_ctx.FD_INFO_IPV4() or s_ctx.FD_INFO_IPV6()
                source = s_node.getText()
                d_ctx = ip_addr_ctxs[1]
                d_node = d_ctx.FD_INFO_IPV4() or d_ctx.FD_INFO_IPV6()
                destination = d_node.getText()

            return classes.IPFileDescriptor(
                number=number,
                protocol=ctx.FD_SOCKET_PROTOCOL().getText(),
                source=source,
                destination=destination
            )
        elif ctx.FD_SOCKET_PROTOCOL_NETLINK() and ctx.netlink_info():
            netlink_ctx = ctx.netlink_info()

            if netlink_ctx.FD_INFO_NETLINK_PROTOCOL():
                subprotocol = netlink_ctx.FD_INFO_NETLINK_PROTOCOL().getText()
            else:
                subprotocol = None

            return classes.NetlinkSubprotocolFileDescriptor(
                number=number,
                protocol=ctx.FD_SOCKET_PROTOCOL_NETLINK().getText(),
                subprotocol=subprotocol,
                pid=_parse_number(netlink_ctx.FD_INFO_NUMBER().getText())
            )
        elif ctx.FD_SOCKET_PROTOCOL_NETLINK() and ctx.inode_info():
            inode, reference, bind = self.visitInode_info(ctx.inode_info())
            return classes.InodeFileDescriptor(
                number=number,
                protocol=ctx.FD_SOCKET_PROTOCOL_NETLINK().getText(),
                inode=inode,
                reference=reference,
                bind=bind,
            )
        elif ctx.FD_CHARACTER() and ctx.inode_info():
            protocol = ''.join(map(lambda c: c.getText(), ctx.FD_CHARACTER()))
            inode, reference, bind = self.visitInode_info(ctx.inode_info())
            return classes.InodeFileDescriptor(
                number=number,
                protocol=protocol,
                inode=inode,
                reference=reference,
                bind=bind,
            )
        else:
            path = ''.join(map(lambda c: c.getText(), ctx.FD_CHARACTER()))
            return classes.PathFileDescriptor(number, path)

    def visitInode_info(self, ctx: StraceParser.Inode_infoContext
                        ) -> Tuple[int, Optional[int], Optional[str]]:
        """Visit inode info.

        Parameters
        ----------
        ctx : StraceParser.Inode_infoContext
            Inode info context.

        Returns
        -------
        Tuple[int, Optional[int], Optional[str]]
            Parsed inode, referenced inode, and bound value.
        """
        inode = _parse_number(ctx.FD_INFO_NUMBER(0).getText())
        if ctx.FD_INFO_REFERENCE():
            reference = _parse_number(ctx.FD_INFO_NUMBER(1).getText())
        else:
            reference = None
        if ctx.FD_INFO_FILENAME():
            bind = ctx.FD_INFO_FILENAME().getText()[1:-1]
        else:
            bind = None
        return inode, reference, bind

    def visitFunction_call(self, ctx: StraceParser.Function_callContext
                           ) -> classes.FunctionCall:
        """Visit a function call.

        Parameters
        ----------
        ctx : StraceParser.Function_callContext
            Function call context.

        Returns
        -------
        classes.FunctionCall
            Parsed function call.
        """
        return classes.FunctionCall(
            identifier=ctx.IDENTIFIER().getText(),
            arguments=self.visit(ctx.literal_list())
        )

    def visitNumeric_expression(self,
                                ctx: StraceParser.Numeric_expressionContext
                                ) -> classes.NumericExpression:
        """Visit a numeric expression context.

        Parameters
        ----------
        ctx : StraceParser.Numeric_expressionContext
            Numeric expression context from the parse tree.

        Returns
        -------
        classes.NumericExpression
            Numeric expression parsed from ctx.
        """
        return classes.NumericExpression(ctx.getText())

    def visitBoolean_expression(self,
                                ctx: StraceParser.Boolean_expressionContext
                                ) -> classes.BooleanExpression:
        """Visit a boolean expression context.

        Parameters
        ----------
        ctx : StraceParser.Boolean_expressionContext
            Boolean expression context from the parse tree.

        Returns
        -------
        classes.BooleanExpression
            Boolean expression parsed from ctx.
        """
        return classes.BooleanExpression(ctx.getText())

    def visitReturn_notes(self, ctx: StraceParser.Return_notesContext) -> str:
        """Visit a return notes context.

        Parameters
        ----------
        ctx : StraceParser.Return_notesContext
            Return notes context from the parse tree.

        Returns
        -------
        str
            Return notes parsed from ctx..
        """
        return ' '.join(map(lambda t: t.getText(), ctx.getChildren()))

    def visitSignal(self, ctx: StraceParser.SignalContext) -> classes.Signal:
        """Visit a signal context.

        Parameters
        ----------
        ctx : StraceParser.SignalContext
            Signal context from the parse tree.

        Returns
        -------
        classes.Signal
            Signal parsed from ctx.
        """
        return classes.Signal(
            ctx.IDENTIFIER().getText(),
            self.visit(ctx.collection())
        )

    def visitExit_statement(self, ctx: StraceParser.Exit_statementContext
                            ) -> classes.ExitStatement:
        """Visit an exit statement context.

        Parameters
        ----------
        ctx : StraceParser.Exit_statementContext
            Exit statement context from the parse tree.

        Returns
        -------
        classes.ExitStatement
            Exit statement parsed from ctx.
        """
        if ctx.EXITED_WITH():
            return classes.ExitStatement(_parse_number(ctx.NUMBER().getText()))
        else:
            return classes.ExitStatement(ctx.IDENTIFIER().getText(), True)
