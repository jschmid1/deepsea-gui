import urwid
import logging
import logging.config
import salt.client
import yaml
import os


# move that to config
LOG_LEVEL="INFO"
LOG_FILE_PATH="/root/policy.log"

class Helper(object):

    KEYNOTFOUND = '<KEYNOTFOUND>'       # KeyNotFound for dictDiff
    @staticmethod
    def dict_diff(first, second):
        """ Return a dict of keys that differ with another config object.  If a value is
            not found in one fo the configs, it will be represented by KEYNOTFOUND.
            @param first:   Fist dictionary to diff.
            @param second:  Second dicationary to diff.
            @return diff:   Dict of Key => (first.val, second.val)
        """
        diff = {}
        # Check all keys in first dict
        for key in first.keys():
            if (not second.has_key(key)):
                diff[key] = (first[key], KEYNOTFOUND)
            elif (first[key] != second[key]):
                diff[key] = (first[key], second[key])
        # Check all keys in second dict to find missing
        for key in second.keys():
            if (not first.has_key(key)):
                diff[key] = (KEYNOTFOUND, second[key])
        return diff



def _setup_logging():
    """
    Logging configuration
    """
    if LOG_LEVEL == "silent":
        return

    logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            },
        },
        'handlers': {
            'file': {
                'level': LOG_LEVEL.upper(),
                'filename': LOG_FILE_PATH,
                'class': 'logging.FileHandler',
                'formatter': 'standard'
            },
        },
        'loggers': {
            '': {
                'handlers': ['file'],
                'level': LOG_LEVEL.upper(),
                'propagate': True,
            }
        }
    })

logger = logging.getLogger(__name__)

_setup_logging()

class Role(object):
    def __init__(self, name):
        if name == 'storage':
            name = 'osd'
        self.name = name
        self.cfg = Cfg
        self.config_path = self.path()

    def path(self):
        return "/srv/salt/ceph/configuration/files/ceph.conf.d/{}.conf".format(self.name)

    def read_conf(self):
        if os.path.exists(self.config_path):
            return self.cfg(self.config_path, mode='ceph').read()
        else:
            return ""

    def write_conf(self, content):
        if os.path.exists(self.config_path):
            return self.cfg(self.config_path, mode='ceph').write(content)
        else:
            logging.error('No config path found in {}'.format(self.config_path))


class Cfg(object):

    def __init__(self, filename=None, mode='yaml'):
        self.mode = mode
        self.filename = filename
        # Cfg should implement the os.path.exists

    def write(self, content):
        with open(self.filename, 'w') as _fd:
            if self.mode == 'yaml':
                _fd.write(yaml.dump(content))
            elif self.mode == 'ceph':
                # convert back to k=v style
                for key, val in content.iteritems():
                    opt = "{}={}".format(key, val)
                    _fd.write(opt)
            else:
                raise IOError('Dont know how to handle parsing mode {}'.format(mode))
            
    def read(self):
        with open(self.filename, 'r') as _fd:
            if self.mode == 'yaml':
                return yaml.load(_fd)
            elif self.mode == 'ceph':
                loo = [ line.strip() for line in  _fd.readlines() ]
                config = {}
                for entry in loo:
                    # There is a ConfigParser which might be safer :D
                    split = entry.split('=')
                    config[split[0]] = split[1]
                return config
            else:
                raise IOError('Dont know how to handle parsing mode {}'.format(mode))

class Settings(object):

    def __init__(self):
        self.cfg = Cfg
        self.local = salt.client.LocalClient()
        self.master_minion = self.get_master()
        self.target_all = self.deepsea_minions()
        self.pre_check()

    def pre_check(self):
       if not self.master_minion:
           raise ImportError("There is no minion with the master role.")
       if not self.deepsea_minions:
           # actually raise
           self.deepsea_minions = '*'

    @property
    def global_conf(self):
        return self.cfg('/srv/pillar/ceph/stack/global.yml')

    def cluster_conf(self, cluster_name):
        return self.cfg('/srv/pillar/ceph/stack/{}/cluster.yml'.format(cluster_name))

    def deepsea_minions(self):
        return self.call_salt(self.master_minion, 'deepsea_minions').values()[0]

    def get_master(self):
        # Thats not very nice. Parse the file and check for the pillar data to be set..
        # this is TODO
        return self.call_salt('*', 'master_minion').values()[0]

    def get_roles(self):
        return self.call_salt(self.target_all, 'roles')

    def get_hosts(self):
        # make this more lightweight
        return self.get_roles().keys()

    def get_available_roles(self):
        return self.call_salt(self.master_minion, 'available_roles').values()[0]

    def get_clusters(self):
        return self.call_salt(self.master_minion, 'cluster').values()

    def call_salt(self, target, item, cmd='pillar.get', expr_form='compound'):
        return self.local.cmd(target, cmd, [item], expr_form=expr_form)


class Cluster(object):
    
    def __init__(self):
        self._selected_node = None
        self._layout = {}
        self.cfg = Cfg
        self.salt = Settings()
        self.role = Role
        self.local = salt.client.LocalClient()
        self._selections = []
        self._hosts = []
        self._roles = []
        self._clusters = []
        self._global_options = {}
        self._cluster_options = {}

    @property
    def hosts(self):
        return self._hosts

    @hosts.setter
    def hosts(self, hosts):
        self._hosts = hosts

    @property
    def global_options(self):
        return self._global_options

    @global_options.setter
    def global_options(self, opts):
        self._global_options = opts

    @property
    def cluster_options(self):
        return self._cluster_options

    @cluster_options.setter
    def cluster_options(self, opts):
        self._cluster_options = opts

    def role_options(self, role_name):
        return self.role(role_name).read_conf()

    @property
    def roles(self):
        return self._roles

    @roles.setter
    def roles(self, roles):
        self._roles = roles

    @property
    def selections(self):
        return self._selections

    @selections.deleter
    def selections(self):
        del self._selections

    def add_to_selections(self, selections):
        self._selections.append(selections)

    def pop_from_selection(self):
        if len(self._selections) >= 1:
            self._selections.pop()

    @property
    def clusters(self):
        return self._clusters

    @clusters.setter
    def clusters(self, clusters):
        self._clusters = clusters
        
    @property
    def layout(self):
        return self._layout

    @layout.setter
    def layout(self, new_layout):
        self._layout = new_layout

    def find_node_name(self):
        # a 'bit' hacky..
        node_name = set(self.hosts).intersection(self.selections).pop()
        logging.debug('Operating on node: {}'.format(node_name))
        # return the Node object here.
        # raise if None
        return node_name

    def find_role_name(self):
        # a 'bit' hacky..
        role_name = set(self.roles).intersection(self.selections).pop()
        logging.debug('Operating on role: {}'.format(role_name))
        # return the Role object here.
        # raise if None
        return role_name

    def layout_diff(self):
        curr = self.salt.get_roles()
        new = self.layout
        diff = Helper.dict_diff(curr, new)
        return diff 

    def readable_diff(self):
        diff = self.layout_diff()
        text_body = []
        for host, diff in diff.iteritems():
            old = diff[0]
            new = diff[1]
            if len(old) < len(new):
                verb = 'gained'
                role = set(new) - set(old)
            else:
                verb = 'lost'
                role = set(old) - set(new)
            role = list(role)
            text_body.append("{host} {verb} role {role}\n".format(host=host, verb=verb, role=" ".join(role)))
        if text_body:
            return text_body 
        else:
            return ["No Change in config detected"]

    def reverse_view(self):
        # show roles that list nodes
        nodes = []
        role = self.find_role_name()
        logging.info('Found role: {}'.format(role))
        for node, roles in self.layout.iteritems():
            logging.info("Node: {}".format(node))
            logging.info("with roles: {}".format(roles))
            if role in roles:
                nodes.append(node)
        return nodes


def register_position(widget_obj):
    logging.info(widget_obj.label)
    cl.add_to_selections(widget_obj.label)

def menu_button(caption, callback):
    button = urwid.Button(caption)
    urwid.connect_signal(button, 'click', callback)
    urwid.connect_signal(button, 'click', register_position)
    return urwid.AttrMap(button, None, focus_map='reversed')

def sub_menu(caption, choices):
    contents = menu(caption, choices)
    def open_menu(button):
        return top.open_box(contents)
    return menu_button([caption], open_menu)

def menu(title, choices):
    body = [urwid.Text(title), urwid.Divider()]
    body.extend(choices)
    return urwid.ListBox(urwid.SimpleFocusListWalker(body))

def host_selector_callback(button):
    response = urwid.Text([u'You chose ', button.label, u'\n'])
    logging.info(cl.layout)
    hosts = cl.reverse_view()
    if not hosts:
        response = urwid.Button(u'There are no hosts assigned to this Role')
    arg_to_open_box = [response]
    for host in hosts:
        user_data = button.label
        check_box_host = urwid.CheckBox(unicode(host))
        # being at that stage, all nodes have that role and are checked therefore
        check_box_host.set_state(True)
        urwid.connect_signal(check_box_host, 'change', register_host_change, user_data)
        arg_to_open_box.append(check_box_host)
    top.open_box(urwid.Filler(urwid.Pile(arg_to_open_box)))

    logging.info("Hosts with selected Role {}".format(hosts))

def role_selector_callback(button):
    response = urwid.Text([u'You chose ', button.label, u'\n'])
    args_to_open_box = [response]
    node_name = cl.find_node_name()
    for role in cl.roles:
        check_box_role = urwid.CheckBox(u"{}".format(role))
        if role in cl.layout[node_name]:
            check_box_role.set_state(True)
        user_data = button.label
        urwid.connect_signal(check_box_role, 'change', register_role_change, user_data)
        args_to_open_box.append(check_box_role)
    top.open_box(urwid.Filler(urwid.Pile(args_to_open_box)))

def conf_selector_callback(button):
    response = urwid.Text([u'You chose ', button.label, u'\n'])
    top.open_box(urwid.Filler(urwid.Pile([response])))

def cluster_selector_callback(button):
    response = urwid.Text([u'You chose ', button.label, u'\n'])
    top.open_box(urwid.Filler(urwid.Pile([response])))

def register_conf_change(obj, dunno):
    logging.info("Current layout: {}".format(layout))

def item_chosen(button):
    response = urwid.Text([u'You chose ', button.label, u'\n'])
    done = menu_button(u'Ok', exit_program)
    top.open_box(urwid.Filler(urwid.Pile([response, done])))

def item_edit_role(button):
    config_option = button.label
    text_edit_cap1 = ('editcp', u"{}: ".format(button.label))

    # we already loaded this, save it somewhere
    role = cl.find_role_name()
    config_value = cl.role_options(role)[config_option]

    text_edit_text1 = u"{}".format(config_value)
    #ask = urwid.AttrWrap(urwid.Edit(text_edit_cap1, text_edit_text1), 'editbx', 'editfc')
    ask = urwid.Edit(text_edit_cap1, text_edit_text1)
    button = urwid.Button(u'Save')
    reply = urwid.Text(u'')
    div = urwid.Divider()
    pile = urwid.Pile([ask, div, reply, div, button])
    #
    def on_ask_change(edit, new_edit_text):
        reply.set_text(new_edit_text)
    # Decorations of Edit -> AttrWrap can not be connected to signals

    urwid.connect_signal(ask, 'change', on_ask_change)
    user_data = {'key': config_option, 'value': reply, 'role': role}
    urwid.connect_signal(button, 'click', save_role_config_option, user_data)
    topo = urwid.Filler(pile, valign='top')
    top.open_box(topo)

def layout_diff(button):
    config_option = button.label
    diff = cl.readable_diff()
    text = urwid.Text(diff)
    div = urwid.Divider()
    save = urwid.Button(u'Save')
    #urwid.connect_signal(save, 'click', save_role_change, user_data)
    reset = urwid.Button(u'Reset')
    #urwid.connect_signal(reset, 'click', reset_role_change, user_data)
    pile = urwid.Pile([text, div, save, reset])
    topo = urwid.Filler(pile, valign='top')
    top.open_box(topo)

def item_edit(button):
    config_option = button.label
    text_edit_cap1 = ('editcp', u"{}: ".format(button.label))
    config_value = cl.global_options[button.label]
    text_edit_text1 = u"{}".format(config_value)
    #ask = urwid.AttrWrap(urwid.Edit(text_edit_cap1, text_edit_text1), 'editbx', 'editfc')
    ask = urwid.Edit(text_edit_cap1, text_edit_text1)
    button = urwid.Button(u'Save')
    reply = urwid.Text(u'')
    div = urwid.Divider()
    pile = urwid.Pile([ask, div, reply, div, button])
    #
    def on_ask_change(edit, new_edit_text):
        reply.set_text(new_edit_text)
    # Decorations of Edit -> AttrWrap can not be connected to signals

    urwid.connect_signal(ask, 'change', on_ask_change)
    user_data = {'key': config_option, 'value': reply}
    urwid.connect_signal(button, 'click', save_global_config_option, user_data)
    topo = urwid.Filler(pile, valign='top')
    top.open_box(topo)

def saved_callback(obj):
    saved_flag = ('key', " SAVED")
    if saved_flag not in footer_text:
        footer_text.append(saved_flag)
        footer = urwid.AttrMap(urwid.Text(footer_text), 'foot')
        view.footer = footer

def error_saving_callback(obj):
    error_flag = ('error', " Error saving")
    if error_flag not in header_text:
        header_text.append(error_flag)
        header = urwid.AttrMap(urwid.Text(header_text), 'header')
        view.header = header

# refactor to be more generic
def item_edit_cluster(button):
    config_option = button.label
    text_edit_cap1 = ('editcp', u"{}: ".format(button.label))

    config_value = cl.cluster_options[button.label]
    text_edit_text1 = u"{}".format(config_value)
    #ask = urwid.AttrWrap(urwid.Edit(text_edit_cap1, text_edit_text1), 'editbx', 'editfc')
    ask = urwid.Edit(text_edit_cap1, text_edit_text1)
    button = urwid.Button(u'Save')
    reply = urwid.Text(u'')
    div = urwid.Divider()
    pile = urwid.Pile([ask, div, reply, div, button])
    #
    def on_ask_change(edit, new_edit_text):
        reply.set_text(new_edit_text)
    # Decorations of Edit -> AttrWrap can not be connected to signals

    urwid.connect_signal(ask, 'change', on_ask_change)
    #                                                                       # STATIC, change
    user_data = {'key': config_option, 'value': reply, 'type': 'cluster', 'cluster': 'ceph'}
    urwid.connect_signal(button, 'click', save_cluster_config_option, user_data)
    topo = urwid.Filler(pile, valign='top')
    top.open_box(topo)

# should be moved to Cfg
def save_cluster_config_option(obj, user_data):
    cluster = str(user_data['cluster'])
    key = str(user_data['key'])
    value = str(user_data['value'].text)
    if value != '':
        if key in cl.cluster_options:
            cl.cluster_options[key] = value
        else:
            logging.info('handle this case')
        logging.info('Saved config option successfully. new value: {}'.format(value))
        logging.info(cl.cluster_options)
        
        try:
            cfg.cluster_conf(cluster).write(cl.cluster_options)
            saved_callback('ok')
        except:
            error_saving_callback('notok')
    else:
        logging.info('No Change in configuration. Not saving.')

def save_role_config_option(obj, user_data):
    role = str(user_data['role'])
    key = str(user_data['key'])
    value = str(user_data['value'].text)
    # Switch to getter and setter
    content = cl.role_options(role)
    if value != '':
        if key in content:
            content[key] = value
        else:
            logging.info('handle this case')
        logging.info('Saved config option successfully. new value: {}'.format(value))
        logging.info(content)
        
        try:
            Role(role).write_conf(content)
            saved_callback('ok')
        except:
            error_saving_callback('notok')
    else:
        logging.info('No Change in configuration. Not saving.')

def save_global_config_option(obj, user_data):
    key = str(user_data['key'])
    value = str(user_data['value'].text)
    if value != '':
        if key in cl.global_options:
            cl.global_options[key] = value
        else:
            logging.info('handle this case')
        logging.info('Saved config option successfully. new value: {}'.format(value))
        logging.info(cl.global_options)
        try:
            cfg.global_conf.write(cl.global_options)
            saved_callback('ok')
        except:
            error_saving_callback('notok')
    else:
        logging.info('No Change in configuration. Not saving.')

def register_role_change(obj, dunno, node_name):
    # True seems to be unchecked
    layout = cl.layout
    logging.info("Current layout: {}".format(layout))
    node_name = cl.find_node_name()
    if obj.get_state() is False:
        logging.info("Selected role {}".format(obj.label))
        cl.layout[node_name].append(obj.label)
    if obj.get_state() is True:
        logging.info("Deselected role {}".format(obj.label))
        cl.layout[node_name].remove(obj.label)

def register_host_change(obj, dunno, node_name):
    # True seems to be unchecked
    layout = cl.layout
    logging.info("Current layout: {}".format(layout))
    role_name = cl.find_role_name()
    if obj.get_state() is False:
        logging.info("Slected role {}".format(obj.label))
        cl.layout[obj.label].append(role_name)
    if obj.get_state() is True:
        logging.info("Deselected role {}".format(obj.label))
        cl.layout[obj.label].remove(role_name)

def exit_program(button):
    raise urwid.ExitMainLoop()



cl = Cluster()
clcl = cl
cfg = Settings()
conf = cfg.global_conf


def load_from_salt():

    cl.layout = cfg.get_roles()
    cl.clusters = cfg.get_clusters()
    cl.roles = cfg.get_available_roles()
    cl.hosts = cfg.get_hosts()
    cl.global_options = cfg.global_conf.read()
    cl.cluster_options = cfg.cluster_conf('ceph').read()

load_from_salt()

clcl.readable_diff()

menu_top = menu(u'Main Menu', [ sub_menu(u'Cluster', 
                                         [ 
                                          sub_menu(u'{}'.format(cluster_name), [ 
                                              sub_menu(u'Roles', [ 
                                                      sub_menu(u'{}'.format(role), [ 
                                                          menu_button(u'Assigned Hosts', host_selector_callback),
                                                          sub_menu(u'Config for Role', [ 
                                                              menu_button(u'{}'.format(config_option), item_edit_role) for config_option in cl.role_options(role)]), 
                                                              ]) for role in cl.roles ]), 
                                              sub_menu(u'Cluster Config', [
                                                  menu_button(u'{}'.format(config_option), item_edit_cluster) for config_option in cl.cluster_options]), 
                                              sub_menu(u'Hosts', [ 
                                                  sub_menu(u'{}'.format(host), [ 
                                                      sub_menu(u'Host options', [ 
                                                          menu_button(u'{}'.format(config_option), item_edit) for config_option in cl.global_options]), 
                                                      menu_button(u'Role Selector', role_selector_callback)
                                                          ]) for host in cl.hosts ]),
                                                 ]) for cluster_name in cl.clusters
                                          ]), 
                                sub_menu(u'Global Configs', 
                                        [ sub_menu(u'Dummy', [ 
                                            menu_button(u'{}'.format(config_option), item_edit) for config_option in cl.global_options])
                                         ]),
                                menu_button(u'Config diff', layout_diff),
                                menu_button(u'Exit', exit_program),
                                        ]) 

class CascadingBoxes(urwid.WidgetPlaceholder):
    max_box_levels = 7

    def __init__(self, box):
        super(CascadingBoxes, self).__init__(urwid.SolidFill(u' '))
        self.box_level = 0
        self.open_box(box)

    def open_box(self, box):
        self.original_widget = urwid.Overlay(urwid.LineBox(box),
            self.original_widget,
            align='center', width=('relative', 100),
            valign='middle', height=('relative', 100),
            min_width=24, min_height=8,
            left=self.box_level * 3,
            right=(self.max_box_levels - self.box_level - 1) * 3,
            top=self.box_level * 2,
            bottom=(self.max_box_levels - self.box_level - 1) * 2)
        self.box_level += 1

    def keypress(self, size, key):
        if key == 'esc' and self.box_level > 1 or key == 'q' and self.box_level > 1:
            self.original_widget = self.original_widget[0]
            self.box_level -= 1
            cl.pop_from_selection()
            default_footer()
            default_header()
        else:
            return super(CascadingBoxes, self).keypress(size, key)

# Make this less hacky
def default_footer():
    saved_flag = ('key', " SAVED")
    if saved_flag in footer_text:
        footer_text.remove(saved_flag)
        footer = urwid.AttrMap(urwid.Text(footer_text), 'foot')
        view.footer = footer

def default_header():
    error_flag = ('error', " Error saving")
    if error_flag in header_text:
        header_text.remove(error_flag)
        header = urwid.AttrMap(urwid.Text(header_text), 'header')
        view.header = header

# Classify that to access view.footer/header instead of accessing this globally
#import pdb;pdb.set_trace()
urwid.command_map['h'] = urwid.CURSOR_LEFT
urwid.command_map['j'] = urwid.CURSOR_DOWN
urwid.command_map['k'] = urwid.CURSOR_UP
urwid.command_map['l'] = urwid.CURSOR_RIGHT
palette = [
    ('body','black','dark cyan', 'standout'),
    ('foot','light gray', 'black'),
    ('key','light cyan', 'black', 'underline'),
    ('title', 'white', 'black',),
    ('editfc','white', 'dark blue', 'bold'),
    ('editbx','light gray', 'dark blue'),
    ('editcp','black','light gray', 'standout'),
    ('error','light red','black', 'bold'),
    ]

footer_text = [
    ('title', "SES Configurator"), "  ",
    ('key', "UP, j"), ", ", ('key', "DOWN, k"), 
    "  move view  ",
    ('key', "Q or ESC"), " moves one layer down",
    ]
header_text = [('title', "SES Configurator")]

footer = urwid.AttrMap(urwid.Text(footer_text), 'foot')
header = urwid.AttrMap(urwid.Text(header_text), 'header')
top = CascadingBoxes(menu_top)
view = urwid.Frame(top, footer=footer, header=header)
loop = urwid.MainLoop(view, palette)
loop.run()
