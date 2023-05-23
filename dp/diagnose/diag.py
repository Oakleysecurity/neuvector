#!/usr/bin/python

import json
import os
import pprint
import socket
import sys

import click

RECV_BUFFER_SIZE = 8192  # 定义了接收缓冲区大小
SERVER_SOCKET = "/tmp/dp_ctrl.sock"  # dp_ctrl服务端套接字
CLIENT_SOCKET = "/tmp/dp_ctrl_client.%d"  # 客户端套接字路径

# 用于维护与服务端之间的通信，并在对象销毁时自动关闭套接字，并删除客户端套接字文件。
class CtxData(object):
    def __init__(self):
        self.local_path = CLIENT_SOCKET % os.getpid()

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(self.local_path)
        try:
            sock.connect(SERVER_SOCKET)
        except socket.error, msg:
            click.echo("Unable to connect to dp_ctrl socket: %s" % msg)
            sys.exit(1)

        self.sock = sock

    def __del__(self):
        self.sock.close()
        os.remove(self.local_path)

@click.group()
@click.pass_context
def cli(ctx):
    ctx.obj = CtxData()

# -- session

@cli.group()
@click.pass_obj
def session(data):
    """Session operation."""

@session.command()
@click.pass_obj
def list(data):    #session组命令一：用于列出所有会话
    body = {"ctrl_list_session": dict()}
    data.sock.sendall(json.dumps(body))

    while True:
        resp = json.loads(data.sock.recv(RECV_BUFFER_SIZE))
        pprint.pprint(resp["sessions"])
        if not resp["more"]:
            break

@session.command()   #这是一个Python装饰器，用于将函数注册为session组的子命令。
@click.pass_obj  #用于传递上下文数据到每个子命令中，从而实现共享状态。
def count(data):  #session组命令二：计算当前会话数
    body = {"ctrl_count_session": dict()}
    data.sock.sendall(json.dumps(body))

    resp = json.loads(data.sock.recv(RECV_BUFFER_SIZE))
    click.echo(resp["dp_count_session"])

# -- debug

@cli.group()
@click.pass_obj
def debug(data):
    """Debug operation."""

@debug.command()
@click.argument('cat', type=click.Choice(['all', 'init', 'error', 'ctrl', 'packet',
                                          'session', 'timer', 'tcp', 'parser']))
@click.pass_obj
def enable(data, cat):  #debug组命令一：启用调试信息
    """Enable debug category."""
    body = {"ctrl_set_debug": {"categories": ["+%s" % cat]}}
    data.sock.sendall(json.dumps(body))

@debug.command()
@click.argument('cat', type=click.Choice(['all', 'init', 'error', 'ctrl', 'packet',
                                          'session', 'timer', 'tcp', 'parser']))
@click.pass_obj
def disable(data, cat):  #debug组命令二：禁用调试信息
    """Disable debug category."""
    body = {"ctrl_set_debug": {"categories": ["-%s" % cat]}}
    data.sock.sendall(json.dumps(body))

@debug.command()
@click.pass_obj
def show(data):   #debug组命令三：显示调试信息
    """Show debug setting."""
    body = {"ctrl_get_debug": dict()}
    data.sock.sendall(json.dumps(body))

    resp = json.loads(data.sock.recv(RECV_BUFFER_SIZE))
    pprint.pprint(resp["dp_debug"])

# -- done


if __name__ == '__main__':
    cli()
