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
                          (rule.pattern(0),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.calculate_score: got unexpected plan from when clause 1"
            with engine.prove(rule.rule_base.root_name, 'administrator', context,
                              (rule.pattern(1),)) \
              as gen_2:
              for x_2 in gen_2:
                assert x_2 is None, \
                  "rules.calculate_score: got unexpected plan from when clause 2"
                with engine.prove(rule.rule_base.root_name, 'windows_update', context,
                                  (rule.pattern(2),)) \
                  as gen_3:
                  for x_3 in gen_3:
                    assert x_3 is None, \
                      "rules.calculate_score: got unexpected plan from when clause 3"
                    with engine.prove(rule.rule_base.root_name, 'firewall', context,
                                      (rule.pattern(3),)) \
                      as gen_4:
                      for x_4 in gen_4:
                        assert x_4 is None, \
                          "rules.calculate_score: got unexpected plan from when clause 4"
                        with engine.prove(rule.rule_base.root_name, 'malware', context,
                                          (rule.pattern(4),)) \
                          as gen_5:
                          for x_5 in gen_5:
                            assert x_5 is None, \
                              "rules.calculate_score: got unexpected plan from when clause 5"
                            with engine.prove(rule.rule_base.root_name, 'uac', context,
                                              (rule.pattern(5),)) \
                              as gen_6:
                              for x_6 in gen_6:
                                assert x_6 is None, \
                                  "rules.calculate_score: got unexpected plan from when clause 6"
                                mark7 = context.mark(True)
                                if rule.pattern(6).match_data(context, context,
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
        with engine.prove('questions', 'ask_password', context,
                          (rule.pattern(0),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.password_very_weak: got unexpected plan from when clause 1"
            if rate_password_strength(context.lookup_data('pass')) == 0:
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
        with engine.prove('questions', 'ask_password', context,
                          (rule.pattern(0),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.password_weak: got unexpected plan from when clause 1"
            if rate_password_strength(context.lookup_data('pass')) == 1:
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
        with engine.prove('questions', 'ask_password', context,
                          (rule.pattern(0),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.password_moderate: got unexpected plan from when clause 1"
            if rate_password_strength(context.lookup_data('pass')) == 2:
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
        with engine.prove('questions', 'ask_password', context,
                          (rule.pattern(0),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.password_strong: got unexpected plan from when clause 1"
            if rate_password_strength(context.lookup_data('pass')) == 3:
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
        with engine.prove('questions', 'ask_password', context,
                          (rule.pattern(0),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.password_very_strong: got unexpected plan from when clause 1"
            if rate_password_strength(context.lookup_data('pass')) == 4:
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
        with engine.prove('questions', 'no_of_administrators', context,
                          (rule.pattern(0),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.single_administrator: got unexpected plan from when clause 1"
            if context.lookup_data('admins') == 1:
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
        with engine.prove('questions', 'no_of_administrators', context,
                          (rule.pattern(0),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.multiple_administrator: got unexpected plan from when clause 1"
            if context.lookup_data('admins') <= 3 and context.lookup_data('admins') > 1:
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
        with engine.prove('questions', 'no_of_administrators', context,
                          (rule.pattern(0),)) \
          as gen_1:
          for x_1 in gen_1:
            assert x_1 is None, \
              "rules.too_many_administrator: got unexpected plan from when clause 1"
            if context.lookup_data('admins') > 3:
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
        if windows_update_status() == False:
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
        if windows_update_status() == True:
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
        if firewall_status() == True:
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
        if firewall_status() == False:
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
        if malware_count() == 0:
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
        if malware_count() <= 5 and malware_count() > 0:
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
        if malware_count() > 5:
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
        if uac_status() == True:
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
        if uac_status() == False:
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
                  (contexts.variable('score'),),
                  (),
                  (contexts.variable('s1'),
                   contexts.variable('s6'),
                   contexts.variable('s2'),
                   contexts.variable('s3'),
                   contexts.variable('s4'),
                   contexts.variable('s5'),
                   contexts.variable('score'),))
  
  bc_rule.bc_rule('password_very_weak', This_rule_base, 'password',
                  password_very_weak, None,
                  (pattern.pattern_literal(0),),
                  (),
                  (contexts.variable('pass'),))
  
  bc_rule.bc_rule('password_weak', This_rule_base, 'password',
                  password_weak, None,
                  (pattern.pattern_literal(5),),
                  (),
                  (contexts.variable('pass'),))
  
  bc_rule.bc_rule('password_moderate', This_rule_base, 'password',
                  password_moderate, None,
                  (pattern.pattern_literal(10),),
                  (),
                  (contexts.variable('pass'),))
  
  bc_rule.bc_rule('password_strong', This_rule_base, 'password',
                  password_strong, None,
                  (pattern.pattern_literal(15),),
                  (),
                  (contexts.variable('pass'),))
  
  bc_rule.bc_rule('password_very_strong', This_rule_base, 'password',
                  password_very_strong, None,
                  (pattern.pattern_literal(20),),
                  (),
                  (contexts.variable('pass'),))
  
  bc_rule.bc_rule('single_administrator', This_rule_base, 'administrator',
                  single_administrator, None,
                  (pattern.pattern_literal(10),),
                  (),
                  (contexts.variable('admins'),))
  
  bc_rule.bc_rule('multiple_administrator', This_rule_base, 'administrator',
                  multiple_administrator, None,
                  (pattern.pattern_literal(5),),
                  (),
                  (contexts.variable('admins'),))
  
  bc_rule.bc_rule('too_many_administrator', This_rule_base, 'administrator',
                  too_many_administrator, None,
                  (pattern.pattern_literal(0),),
                  (),
                  (contexts.variable('admins'),))
  
  bc_rule.bc_rule('not_updated', This_rule_base, 'windows_update',
                  not_updated, None,
                  (pattern.pattern_literal(0),),
                  (),
                  ())
  
  bc_rule.bc_rule('updated', This_rule_base, 'windows_update',
                  updated, None,
                  (pattern.pattern_literal(15),),
                  (),
                  ())
  
  bc_rule.bc_rule('firewall_on', This_rule_base, 'firewall',
                  firewall_on, None,
                  (pattern.pattern_literal(20),),
                  (),
                  ())
  
  bc_rule.bc_rule('firewall_off', This_rule_base, 'firewall',
                  firewall_off, None,
                  (pattern.pattern_literal(0),),
                  (),
                  ())
  
  bc_rule.bc_rule('no_malware', This_rule_base, 'malware',
                  no_malware, None,
                  (pattern.pattern_literal(30),),
                  (),
                  ())
  
  bc_rule.bc_rule('some_malware', This_rule_base, 'malware',
                  some_malware, None,
                  (pattern.pattern_literal(10),),
                  (),
                  ())
  
  bc_rule.bc_rule('lots_of_malware', This_rule_base, 'malware',
                  lots_of_malware, None,
                  (pattern.pattern_literal(0),),
                  (),
                  ())
  
  bc_rule.bc_rule('uac_on', This_rule_base, 'uac',
                  uac_on, None,
                  (pattern.pattern_literal(5),),
                  (),
                  ())
  
  bc_rule.bc_rule('uac_off', This_rule_base, 'uac',
                  uac_off, None,
                  (pattern.pattern_literal(0),),
                  (),
                  ())

from functions import *

Krb_filename = '..\\rules.krb'
Krb_lineno_map = (
    ((14, 18), (2, 2)),
    ((20, 25), (4, 4)),
    ((26, 31), (5, 5)),
    ((32, 37), (6, 6)),
    ((38, 43), (7, 7)),
    ((44, 49), (8, 8)),
    ((50, 55), (9, 9)),
    ((58, 58), (10, 10)),
    ((74, 78), (13, 13)),
    ((80, 85), (15, 15)),
    ((86, 86), (16, 16)),
    ((87, 87), (17, 18)),
    ((100, 104), (21, 21)),
    ((106, 111), (23, 23)),
    ((112, 112), (24, 24)),
    ((113, 113), (25, 26)),
    ((126, 130), (29, 29)),
    ((132, 137), (31, 31)),
    ((138, 138), (32, 32)),
    ((139, 139), (33, 34)),
    ((152, 156), (37, 37)),
    ((158, 163), (39, 39)),
    ((164, 164), (40, 40)),
    ((165, 165), (41, 42)),
    ((178, 182), (45, 45)),
    ((184, 189), (47, 47)),
    ((190, 190), (48, 48)),
    ((191, 191), (49, 50)),
    ((204, 208), (53, 53)),
    ((210, 215), (55, 55)),
    ((216, 216), (56, 56)),
    ((217, 217), (57, 58)),
    ((230, 234), (61, 61)),
    ((236, 241), (63, 63)),
    ((242, 242), (64, 64)),
    ((243, 243), (65, 66)),
    ((256, 260), (69, 69)),
    ((262, 267), (71, 71)),
    ((268, 268), (72, 72)),
    ((269, 269), (73, 74)),
    ((282, 286), (77, 77)),
    ((288, 288), (79, 79)),
    ((289, 290), (80, 82)),
    ((303, 307), (85, 85)),
    ((309, 309), (87, 87)),
    ((310, 311), (88, 90)),
    ((324, 328), (93, 93)),
    ((330, 330), (95, 95)),
    ((331, 332), (96, 98)),
    ((345, 349), (101, 101)),
    ((351, 351), (103, 103)),
    ((352, 353), (104, 106)),
    ((366, 370), (109, 109)),
    ((372, 372), (111, 111)),
    ((373, 374), (112, 114)),
    ((387, 391), (117, 117)),
    ((393, 393), (119, 119)),
    ((394, 395), (120, 122)),
    ((408, 412), (125, 125)),
    ((414, 414), (127, 127)),
    ((415, 416), (128, 130)),
    ((429, 433), (133, 133)),
    ((435, 435), (135, 135)),
    ((436, 437), (136, 138)),
    ((450, 454), (141, 141)),
    ((456, 456), (143, 143)),
    ((457, 458), (144, 146)),
)
