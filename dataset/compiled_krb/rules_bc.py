# rules_bc.py

from pyke import contexts, pattern, bc_rule

pyke_version = '1.1.1'
compiler_version = 1

def calculate_score(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        with engine.prove(rule.rule_base.root_name, 'password', context,
                          (rule.pattern(0),
                           rule.pattern(1),
                           rule.pattern(2),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.calculate_score: got unexpected plan from when clause 1"
            with engine.prove(rule.rule_base.root_name, 'administrator', context,
                              (rule.pattern(3),
                               rule.pattern(4),
                               rule.pattern(5),)) \
              as gen_2:
              for x_2 in gen_2:
                assert x_2 is None, \
                  "rules.calculate_score: got unexpected plan from when clause 2"
                with engine.prove(rule.rule_base.root_name, 'windows_update', context,
                                  (rule.pattern(6),
                                   rule.pattern(7),
                                   rule.pattern(8),)) \
                  as gen_3:
                  for x_3 in gen_3:
                    assert x_3 is None, \
                      "rules.calculate_score: got unexpected plan from when clause 3"
                    with engine.prove(rule.rule_base.root_name, 'firewall', context,
                                      (rule.pattern(9),
                                       rule.pattern(10),
                                       rule.pattern(11),)) \
                      as gen_4:
                      for x_4 in gen_4:
                        assert x_4 is None, \
                          "rules.calculate_score: got unexpected plan from when clause 4"
                        with engine.prove(rule.rule_base.root_name, 'malware', context,
                                          (rule.pattern(12),
                                           rule.pattern(13),
                                           rule.pattern(14),)) \
                          as gen_5:
                          for x_5 in gen_5:
                            assert x_5 is None, \
                              "rules.calculate_score: got unexpected plan from when clause 5"
                            with engine.prove(rule.rule_base.root_name, 'uac', context,
                                              (rule.pattern(15),
                                               rule.pattern(16),
                                               rule.pattern(17),)) \
                              as gen_6:
                              for x_6 in gen_6:
                                assert x_6 is None, \
                                  "rules.calculate_score: got unexpected plan from when clause 6"
                                mark7 = context.mark(True)
                                if rule.pattern(18).match_data(context, context,
                                        sum(context.lookup_data('s1'), context.lookup_data('s2'), context.lookup_data('s3'), context.lookup_data('s4'), context.lookup_data('s5'), context.lookup_data('s6'))):
                                  context.end_save_all_undo()
                                  rule.rule_base.num_bc_rule_successes += 1
                                  yield
                                else: context.end_save_all_undo()
                                context.undo_to_mark(mark7)
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def password_very_weak(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v1') == 0:
          print('Your password is very weak. Change it immediately!')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def password_weak(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v1') == 1:
          print('Your password is weak. Change your password!')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def password_moderate(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v1') == 2:
          print('Your password is alright. Change your password!')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def password_strong(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v1') == 3:
          print('Your password is strong')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def password_very_strong(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v1') == 4:
          print('Your password is very strong')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def single_administrator(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v2') == 1:
          print('Good job! Single administrator is most secure.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def multiple_administrator(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v2') <= 3 and context.lookup_data('v2') > 1:
          print('You have multiple administrators.It is advisable to have a single administrator.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def too_many_administrator(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v2') > 3:
          print('You have too many administrators!')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def not_updated(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v3') == False:
          print('______________________________________________________________________________')
          print('Update your Windows for latest security patches.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def updated(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v3') == True:
          print('______________________________________________________________________________')
          print('Good work! Your Windows is UpToDate')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def firewall_on(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v4') == True:
          print('______________________________________________________________________________')
          print('Good job! A firewall protects you from the net.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def firewall_off(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v4') == False:
          print('______________________________________________________________________________')
          print('Enable your firewall to protect yourself from outside threats from the internet.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def no_malware(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v5') == 0:
          print('______________________________________________________________________________')
          print('Excellent! Your system has no malware.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def some_malware(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v5') <= 5 and context.lookup_data('v5') > 0:
          print('______________________________________________________________________________')
          print('Your system is infected with malware. Install an antivirus to clear them out.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def lots_of_malware(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v5') > 5:
          print('______________________________________________________________________________')
          print('Your system is flooded with malware. Perform a system reset and download a reliable antivirus.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def uac_on(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v6') == True:
          print('______________________________________________________________________________')
          print('Good work! Your UAC is on. It protects you from other users with malicious intent.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def uac_off(rule, arg_patterns, arg_context):
  engine = rule.rule_base.engine
  patterns = rule.goal_arg_patterns()
  if len(arg_patterns) == len(patterns):
    context = contexts.bc_context(rule)
    try:
      if all(map(lambda pat, arg:
                   pat.match_pattern(context, context,
                                     arg, arg_context),
                 patterns,
                 arg_patterns)):
        rule.rule_base.num_bc_rules_matched += 1
        if context.lookup_data('v6') == False:
          print('______________________________________________________________________________')
          print('Turn on your UAC from settings to safeguard your system from malicious users.')
          rule.rule_base.num_bc_rule_successes += 1
          yield
        rule.rule_base.num_bc_rule_failures += 1
    finally:
      context.done()

def populate(engine):
  This_rule_base = engine.get_create('rules')
  
  bc_rule.bc_rule('calculate_score', This_rule_base, 'calculate_score',
                  calculate_score, None,
                  (contexts.variable('score'),
                   contexts.variable('l1'),
                   contexts.variable('l2'),
                   contexts.variable('l3'),
                   contexts.variable('l4'),
                   contexts.variable('l5'),
                   contexts.variable('l6'),
                   contexts.variable('v1'),
                   contexts.variable('v2'),
                   contexts.variable('v3'),
                   contexts.variable('v4'),
                   contexts.variable('v5'),
                   contexts.variable('v6'),),
                  (),
                  (contexts.variable('s1'),
                   contexts.variable('l1'),
                   contexts.variable('v1'),
                   contexts.variable('s2'),
                   contexts.variable('l2'),
                   contexts.variable('v2'),
                   contexts.variable('s3'),
                   contexts.variable('l3'),
                   contexts.variable('v3'),
                   contexts.variable('s4'),
                   contexts.variable('l4'),
                   contexts.variable('v4'),
                   contexts.variable('s5'),
                   contexts.variable('l5'),
                   contexts.variable('v5'),
                   contexts.variable('s6'),
                   contexts.variable('l6'),
                   contexts.variable('v6'),
                   contexts.variable('score'),))
  
  bc_rule.bc_rule('password_very_weak', This_rule_base, 'password',
                  password_very_weak, None,
                  (pattern.pattern_literal(0),
                   pattern.pattern_literal(0),
                   contexts.variable('v1'),),
                  (),
                  ())
  
  bc_rule.bc_rule('password_weak', This_rule_base, 'password',
                  password_weak, None,
                  (pattern.pattern_literal(5),
                   pattern.pattern_literal(1),
                   contexts.variable('v1'),),
                  (),
                  ())
  
  bc_rule.bc_rule('password_moderate', This_rule_base, 'password',
                  password_moderate, None,
                  (pattern.pattern_literal(10),
                   pattern.pattern_literal(2),
                   contexts.variable('v1'),),
                  (),
                  ())
  
  bc_rule.bc_rule('password_strong', This_rule_base, 'password',
                  password_strong, None,
                  (pattern.pattern_literal(15),
                   pattern.pattern_literal(3),
                   contexts.variable('v1'),),
                  (),
                  ())
  
  bc_rule.bc_rule('password_very_strong', This_rule_base, 'password',
                  password_very_strong, None,
                  (pattern.pattern_literal(20),
                   pattern.pattern_literal(4),
                   contexts.variable('v1'),),
                  (),
                  ())
  
  bc_rule.bc_rule('single_administrator', This_rule_base, 'administrator',
                  single_administrator, None,
                  (pattern.pattern_literal(10),
                   pattern.pattern_literal(0),
                   contexts.variable('v2'),),
                  (),
                  ())
  
  bc_rule.bc_rule('multiple_administrator', This_rule_base, 'administrator',
                  multiple_administrator, None,
                  (pattern.pattern_literal(5),
                   pattern.pattern_literal(1),
                   contexts.variable('v2'),),
                  (),
                  ())
  
  bc_rule.bc_rule('too_many_administrator', This_rule_base, 'administrator',
                  too_many_administrator, None,
                  (pattern.pattern_literal(0),
                   pattern.pattern_literal(2),
                   contexts.variable('v2'),),
                  (),
                  ())
  
  bc_rule.bc_rule('not_updated', This_rule_base, 'windows_update',
                  not_updated, None,
                  (pattern.pattern_literal(0),
                   pattern.pattern_literal(0),
                   contexts.variable('v3'),),
                  (),
                  ())
  
  bc_rule.bc_rule('updated', This_rule_base, 'windows_update',
                  updated, None,
                  (pattern.pattern_literal(15),
                   pattern.pattern_literal(1),
                   contexts.variable('v3'),),
                  (),
                  ())
  
  bc_rule.bc_rule('firewall_on', This_rule_base, 'firewall',
                  firewall_on, None,
                  (pattern.pattern_literal(20),
                   pattern.pattern_literal(0),
                   contexts.variable('v4'),),
                  (),
                  ())
  
  bc_rule.bc_rule('firewall_off', This_rule_base, 'firewall',
                  firewall_off, None,
                  (pattern.pattern_literal(0),
                   pattern.pattern_literal(1),
                   contexts.variable('v4'),),
                  (),
                  ())
  
  bc_rule.bc_rule('no_malware', This_rule_base, 'malware',
                  no_malware, None,
                  (pattern.pattern_literal(30),
                   pattern.pattern_literal(0),
                   contexts.variable('v5'),),
                  (),
                  ())
  
  bc_rule.bc_rule('some_malware', This_rule_base, 'malware',
                  some_malware, None,
                  (pattern.pattern_literal(10),
                   pattern.pattern_literal(1),
                   contexts.variable('v5'),),
                  (),
                  ())
  
  bc_rule.bc_rule('lots_of_malware', This_rule_base, 'malware',
                  lots_of_malware, None,
                  (pattern.pattern_literal(0),
                   pattern.pattern_literal(2),
                   contexts.variable('v5'),),
                  (),
                  ())
  
  bc_rule.bc_rule('uac_on', This_rule_base, 'uac',
                  uac_on, None,
                  (pattern.pattern_literal(5),
                   pattern.pattern_literal(0),
                   contexts.variable('v6'),),
                  (),
                  ())
  
  bc_rule.bc_rule('uac_off', This_rule_base, 'uac',
                  uac_off, None,
                  (pattern.pattern_literal(0),
                   pattern.pattern_literal(1),
                   contexts.variable('v6'),),
                  (),
                  ())

from driver import *

Krb_filename = '..\\rules.krb'
Krb_lineno_map = (
    ((14, 18), (2, 2)),
    ((20, 27), (4, 4)),
    ((28, 35), (5, 5)),
    ((36, 43), (6, 6)),
    ((44, 51), (7, 7)),
    ((52, 59), (8, 8)),
    ((60, 67), (9, 9)),
    ((70, 70), (10, 10)),
    ((86, 90), (13, 13)),
    ((92, 92), (17, 17)),
    ((93, 93), (18, 19)),
    ((106, 110), (22, 22)),
    ((112, 112), (26, 26)),
    ((113, 113), (27, 28)),
    ((126, 130), (31, 31)),
    ((132, 132), (35, 35)),
    ((133, 133), (36, 37)),
    ((146, 150), (40, 40)),
    ((152, 152), (44, 44)),
    ((153, 153), (45, 46)),
    ((166, 170), (49, 49)),
    ((172, 172), (53, 53)),
    ((173, 173), (54, 55)),
    ((186, 190), (58, 58)),
    ((192, 192), (62, 62)),
    ((193, 193), (63, 64)),
    ((206, 210), (67, 67)),
    ((212, 212), (71, 71)),
    ((213, 213), (72, 73)),
    ((226, 230), (76, 76)),
    ((232, 232), (80, 80)),
    ((233, 233), (81, 82)),
    ((246, 250), (85, 85)),
    ((252, 252), (87, 87)),
    ((253, 254), (88, 90)),
    ((267, 271), (93, 93)),
    ((273, 273), (95, 95)),
    ((274, 275), (96, 98)),
    ((288, 292), (101, 101)),
    ((294, 294), (103, 103)),
    ((295, 296), (104, 106)),
    ((309, 313), (109, 109)),
    ((315, 315), (111, 111)),
    ((316, 317), (112, 114)),
    ((330, 334), (117, 117)),
    ((336, 336), (119, 119)),
    ((337, 338), (120, 122)),
    ((351, 355), (125, 125)),
    ((357, 357), (127, 127)),
    ((358, 359), (128, 130)),
    ((372, 376), (133, 133)),
    ((378, 378), (135, 135)),
    ((379, 380), (136, 138)),
    ((393, 397), (141, 141)),
    ((399, 399), (143, 143)),
    ((400, 401), (144, 146)),
    ((414, 418), (149, 149)),
    ((420, 420), (151, 151)),
    ((421, 422), (152, 154)),
)
