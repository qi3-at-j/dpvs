#!/usr/bin/env python3

import re
from .log_output import output

INDENT = '    '

#DEBUG=False
#logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO)
#logging.basicConfig(format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s', 
#        level=logging.DEBUG if DEBUG else logging.INFO,
#        filename='/var/log/py_dpvs.log',
#        filemode='w')

class Error(Exception):
    pass


class ParseError(Error):
    pass


def bump_child_depth(obj, depth):
    children = getattr(obj, 'children', [])
    for child in children:
        child._depth = depth + 1
        bump_child_depth(child, child._depth)


class Conf(object):
    def __init__(self, *args):
        self.children = list(args)

    def add(self, *args):
        self.children.extend(args)
        return self.children

    def remove(self, *args):
        for x in args:
            self.children.remove(x)
        return self.children

    def filter(self, btype='', name=''):
        #filtered = []
        #for x in self.children:
        #    if name and isinstance(x, Key) and x.name == name:
        #        filtered.append(x)
        #    elif isinstance(x, Container) and x.__class__.__name__ == btype \
        #            and x.value == name:
        #        filtered.append(x)
        #    elif not name and btype and x.__class__.__name__ == btype:
        #        filtered.append(x)
        #return filtered
        filtered = []
        for x in self.children:
            if name and isinstance(x, Key) and x.name == name:
                filtered.append(x)
            elif isinstance(x, Container) and x.name == btype and x.value == name:
                filtered.append(x)
            elif isinstance(x, Container) and not name and btype and x.name == btype:
                filtered.append(x)
            elif not name and btype and x.__class__.__name__ == btype:
                filtered.append(x)
        return filtered

    @property
    def as_list(self):
        return [x.as_list for x in self.children]

    @property
    def as_dict(self):
        return {'conf': [x.as_dict for x in self.children]}

    @property
    def as_strings(self):
        ret = []
        for x in self.children:
            if isinstance(x, (Key, Comment)):
                ret.append(x.as_strings)
            else:
                for y in x.as_strings:
                    ret.append(y)
        if ret:
            ret[-1] = re.sub('}\n+$', '}\n', ret[-1])
        return ret


class Container(object):
    def __init__(self, value, *args):
        self.name = ''
        self.value = value
        self._depth = 0
        self.children = list(args)
        bump_child_depth(self, self._depth)

    def add(self, *args):
        self.children.extend(args)
        bump_child_depth(self, self._depth)
        return self.children

    def remove(self, *args):
        for x in args:
            self.children.remove(x)
        return self.children

    def filter(self, btype='', name=''):
        #filtered = []
        #for x in self.children:
        #    if name and isinstance(x, Key) and x.name == name:
        #        filtered.append(x)
        #    elif isinstance(x, Container) and x.__class__.__name__ == btype \
        #            and x.value == name:
        #        filtered.append(x)
        #    elif not name and btype and x.__class__.__name__ == btype:
        #        filtered.append(x)
        #return filtered
        filtered = []
        for x in self.children:
            if name and isinstance(x, Key) and x.name == name:
                filtered.append(x)
            elif isinstance(x, Container) and x.name == btype and x.value == name:
                filtered.append(x)
            elif isinstance(x, Container) and not name and btype and x.name == btype:
                filtered.append(x)
            elif not name and btype and x.__class__.__name__ == btype:
                filtered.append(x)
        return filtered

    @property
    def comments(self):
        return [x for x in self.children if isinstance(x, Comment)]

    @property
    def keys(self):
        return [x for x in self.children if isinstance(x, Key)]

    @property
    def as_list(self):
        return [self.name, self.value, [x.as_list for x in self.children]]

    @property
    def as_dict(self):
        dicts = [x.as_dict for x in self.children]
        return {'{0} {1}'.format(self.name, self.value): dicts}

    @property
    def as_strings(self):
        ret = []
        #container_title = (INDENT * self._depth)
        container_title = ''
        container_title += '{0}{1} {{\n'.format(
            self.name, (' {0}'.format(self.value) if self.value else '')
        )
        ret.append(container_title)
        for x in self.children:
            if isinstance(x, Key):
                if 'detect' == x.name or 'description' == x.name:
                    ret.append(INDENT + x.as_strings)
                    continue
                if len(x.as_strings):
                    ret.append(INDENT + x.as_strings)
            elif isinstance(x, Comment):
                if x.inline and len(ret) >= 1:
                    ret[-1] = ret[-1].rstrip('\n') + '  ' + x.as_strings
                else:
                    ret.append(INDENT + x.as_strings)
            elif isinstance(x, Container):
                y = x.as_strings
                ret.append('\n')
                ret.append(INDENT + y[0])
                #ret.append('\n' + y[0])
                for z in y[1:]:
                    ret.append(INDENT + z)
            else:
                y = x.as_strings
                ret.append(INDENT + y)
        ret[-1] = re.sub('}\n+$', '}\n', ret[-1])
        ret.append('}\n\n')
        return ret


class Comment(object):

    def __init__(self, comment, inline=False):
        self.comment = comment
        self.inline = inline

    @property
    def as_list(self):
        return [self.comment]

    @property
    def as_dict(self):
        return {'!': self.comment}
        #return {'#': self.comment}

    @property
    def as_strings(self):
        return '! {0}\n'.format(self.comment)
        #return '# {0}\n'.format(self.comment)


################ modify by hw ###############################
class Block(Container):
    def __init__(self, name, value='', *args):
        super(Block, self).__init__(value, *args)
        self.name = name

################ modify end ###############################

class Key(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    @property
    def as_list(self):
        return [self.name, self.value]

    @property
    def as_dict(self):
        return {self.name: self.value}

    @property
    def as_strings(self):
        if 'detect' == self.name or 'description' == self.name:
            return '{0} "{1}"\n'.format(self.name, self.value)
        if self.value == '' or self.value is None:
            return ''
            #return '{0};\n'.format(self.name)
        if type(self.value) == str and '"' not in self.value and (';' in self.value or '#' in self.value):
            return '{0} "{1}";\n'.format(self.name, self.value)
        return '{0} {1}\n'.format(self.name, self.value)
        #return '{0} {1};\n'.format(self.name, self.value)


def loads(data, conf=True):
    f = Conf() if conf else []
    lopen = []
    index = 0

    key_pattern = re.compile(r'^\s*(<init>)?\s*([^\s#!}]+)\s+("[^"]*"|[^\s{]+)[ \t]*(?!{)(?=\n)')
    block_end_pattern = re.compile(r'^\s*}')
    block_begin_pattern = re.compile(r'^\s*(<init>)?\s*([^\s#!]*)\s+([^\s]+)?\s*{')
    comment_pattern = re.compile(r'^(\s*)[#!][ \r\t\f]*(.*?)\n')

    while True:
        # match key
        m = key_pattern.search(data[index:])
        if m:
            if m.group(1) is None:
                k = m.group(2)
            else:
                k = m.group(1) + ' ' + m.group(2)
            mm = m.group(3).strip('"')
            mm = mm.strip()
            output.debug("Key {0} {1}".format(k, mm))
            key = Key(k, mm)
            if lopen and isinstance(lopen[0], Container):
                lopen[0].add(key)
            else:
                f.add(key) if conf else f.append(key)
            index += m.end()
            continue

        # match end of block
        m = block_end_pattern.search(data[index:])
        if m:
            if isinstance(lopen[0], Container):
                output.debug("Close ({0})".format(lopen[0].name))
                c = lopen[0]
                lopen.pop(0)
                if lopen and isinstance(lopen[0], Container):
                    lopen[0].add(c)
                else:
                    f.add(c) if conf else f.append(c)
            index += m.end()
            continue

        # match begin of block
        m = block_begin_pattern.search(data[index:])
        if m:
            if m.group(1) is None:
                k = m.group(2)
            else:
                k = m.group(1) + ' ' + m.group(2)

            if m.group(3) is None:
                e = Block(k)
                output.debug("Open {}".format(k))
            else:
                e = Block(k, m.group(3))
                output.debug("Open {} -- {}".format(k, m.group(3)))
            lopen.insert(0, e)
            index += m.end()
            continue

        # match comment
        m = comment_pattern.search(data[index:])
        if m:
            output.debug("Comment ({0})".format(m.group(2)))
            c = Comment(m.group(2), inline='\n' not in m.group(1))
            if lopen and isinstance(lopen[0], Container):
                lopen[0].add(c)
            else:
                f.add(c) if conf else f.append(c)
            index += m.end() - 1
            continue

        # error
        if len(lopen):
            output.exception("class:{} name:{} value:{}".format(
                lopen[0].__class__.__name__,
                lopen[0].name,
                lopen[0].value))
            output.error(data[index:index+64])
        break

    return f


def load(fobj):
    return loads(fobj.read())


def loadf(path):
    with open(path, 'r') as f:
        return load(f)


def dumps(obj):
    return ''.join(obj.as_strings)


def dump(obj, fobj):
    fobj.write(dumps(obj))
    return fobj


def dumpf(obj, path):
    with open(path, 'w') as f:
        dump(obj, f)
    return path
