# Generated from StraceParser.g4 by ANTLR 4.8
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .StraceParser import StraceParser
else:
    from StraceParser import StraceParser

# This class defines a complete generic visitor for a parse tree produced by StraceParser.

class StraceParserVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by StraceParser#strace.
    def visitStrace(self, ctx:StraceParser.StraceContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#trace_line.
    def visitTrace_line(self, ctx:StraceParser.Trace_lineContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#syscall.
    def visitSyscall(self, ctx:StraceParser.SyscallContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#syscall_start.
    def visitSyscall_start(self, ctx:StraceParser.Syscall_startContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#syscall_arguments.
    def visitSyscall_arguments(self, ctx:StraceParser.Syscall_argumentsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#syscall_argument.
    def visitSyscall_argument(self, ctx:StraceParser.Syscall_argumentContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#syscall_end.
    def visitSyscall_end(self, ctx:StraceParser.Syscall_endContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#syscall_resumed.
    def visitSyscall_resumed(self, ctx:StraceParser.Syscall_resumedContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#syscall_unfinished.
    def visitSyscall_unfinished(self, ctx:StraceParser.Syscall_unfinishedContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#signal.
    def visitSignal(self, ctx:StraceParser.SignalContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#exit_statement.
    def visitExit_statement(self, ctx:StraceParser.Exit_statementContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#literal.
    def visitLiteral(self, ctx:StraceParser.LiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#literal_value.
    def visitLiteral_value(self, ctx:StraceParser.Literal_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#mapping.
    def visitMapping(self, ctx:StraceParser.MappingContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#literal_list.
    def visitLiteral_list(self, ctx:StraceParser.Literal_listContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#collection.
    def visitCollection(self, ctx:StraceParser.CollectionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#file_descriptor.
    def visitFile_descriptor(self, ctx:StraceParser.File_descriptorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#device_info.
    def visitDevice_info(self, ctx:StraceParser.Device_infoContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#inode_info.
    def visitInode_info(self, ctx:StraceParser.Inode_infoContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#ip_info.
    def visitIp_info(self, ctx:StraceParser.Ip_infoContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#ip_addr.
    def visitIp_addr(self, ctx:StraceParser.Ip_addrContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#netlink_info.
    def visitNetlink_info(self, ctx:StraceParser.Netlink_infoContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#function_call.
    def visitFunction_call(self, ctx:StraceParser.Function_callContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#numeric_expression.
    def visitNumeric_expression(self, ctx:StraceParser.Numeric_expressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#boolean_expression.
    def visitBoolean_expression(self, ctx:StraceParser.Boolean_expressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#return_value.
    def visitReturn_value(self, ctx:StraceParser.Return_valueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by StraceParser#return_notes.
    def visitReturn_notes(self, ctx:StraceParser.Return_notesContext):
        return self.visitChildren(ctx)



del StraceParser