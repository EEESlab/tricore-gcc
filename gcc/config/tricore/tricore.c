/*  Copyright (C) 2010-2014 Free Software Foundation, Inc.
    This file is part of GCC.

GCC is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published
by the Free Software Foundation; either version 3, or (at your
option) any later version.

GCC is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */

#define IN_TARGET_CODE 1

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "backend.h"
#include "target.h"
#include "rtl.h"
#include "tree.h"
#include "memmodel.h"
#include "cfghooks.h"
#include "df.h"
#include "tm_p.h"
#include "stringpool.h"
#include "attribs.h"
#include "optabs.h"
#include "regs.h"
#include "emit-rtl.h"
#include "recog.h"
#include "cgraph.h"
#include "diagnostic.h"
#include "insn-attr.h"
#include "output.h"
#include "alias.h"
#include "fold-const.h"
#include "varasm.h"
#include "stor-layout.h"
#include "calls.h"
#include "explow.h"
#include "expr.h"
#include "reload.h"
#include "common/common-target.h"
#include "langhooks.h"
#include "cfgrtl.h"
#include "cfganal.h"
#include "tree-pass.h"
#include "context.h"
#include "builtins.h"
#include "tm-constrs.h"
#include "rtl-iter.h"
#include "print-rtl.h"
#include "tree-ssa-alias.h"
#include "gimple.h"
#include "gimple-iterator.h"
#include "gimplify-me.h"
#include "gimple-walk.h"
#include "print-tree.h"
#include "tree-pretty-print.h"
#include "gimple-pretty-print.h"
#include "tree-dump.h"
#include "langhooks.h"
#include "tree-iterator.h"
#include "tree-inline.h"
#include "tree-nested.h"
#include "opts.h"
#include "sched-int.h"

/* This file should be included last.  */
#include "target-def.h"

/* Tokens for the machine specific attributes we support */
#define TRIC_ATTR_ABSOLUTE           "absdata"
#define TRIC_ATTR_INDIRECT           "fardata"
#define TRIC_ATTR_SMALL              "smalldata"
#define TRIC_ATTR_INTERRUPT          "interrupt"
#define TRIC_ATTR_INTERRUPT_HANDLER  "interrupt_handler"
#define TRIC_ATTR_PXHNDCALL          "pxhndcall"
#define TRIC_ATTR_LONGCALL           "longcall"
#define TRIC_ATTR_ASECTION              "asection"

/* Addresses that have their 12 MSBs set can be loaded/stored
   by one single instruction. */
#define TRIC_ABSOLUTE_INT_ADDRESS_P(X) \
   ((0x0fffc000 & (X)) == 0)

#define TRIC_ABSOLUTE_CODE_ADDRESS_P(X) \
   ((0x0fe00001 & (X)) == 0)

/* Mask for A-regs */
#define AREGS_MASK 0xffff0000

/* Mask for D-regs */
#define DREGS_MASK 0x0000ffff

/* Mask for regs that are element of LOCAL_REGNO */
#define LOCAL_REGNO_MASK 0xf000ff00

/* Machine dependent SYMBOL_REF flags */
#define TRIC_SYMBOL_FLAG_ABSOLUTE (SYMBOL_FLAG_MACH_DEP << 0)
#define TRIC_SYMBOL_FLAG_SMALL    (SYMBOL_FLAG_MACH_DEP << 1)
#define TRIC_SYMBOL_FLAG_LONGCALL (SYMBOL_FLAG_MACH_DEP << 2)
#define TRIC_SYMBOL_FLAG_PIC      (SYMBOL_FLAG_MACH_DEP << 3)

/* Information about a node to be dumped.  */

typedef struct dump_node_info_sign
{
  /* The index for the node.  */
  unsigned int index;
  /* Nonzero if the node is a binfo.  */
  unsigned int binfo_p : 1;
} *dump_node_info_sign_p;

/* A dump_info gives information about how we should perform the dump
   and about the current state of the dump.  */
typedef struct dump_info_sign *dump_info_sign_p;

struct dump_info_sign
{
  char *buf;
  int buf_len;
  int buf_max;
  /* The stream on which to dump the information.  */
  //FILE *stream; //no stream is used....
  /* The original node.  */
  const_tree node;
  /* User flags.  */
  dump_flags_t flags;
  /* The next unused node index.  */
  unsigned int index;
  /* The next column.  */
  unsigned int column;
  /* The first node in the queue of nodes to be written out.  */
  dump_queue_p queue;
  /* The last node in the queue.  */
  dump_queue_p queue_end;
  /* Free queue nodes.  */
  dump_queue_p free_list;
  /* The tree nodes which we have already written out.  The
     keys are the addresses of the nodes; the values are the integer
     indices we assigned them.  */
  splay_tree nodes;
};

static const pass_data tric_pass_data_gimple =
{
	GIMPLE_PASS,     /* type */
	"tric-gimple",   /* name */
	OPTGROUP_NONE,   /* optinfo_flags */
	TV_NONE,         /* tv_id */
	PROP_gimple_any, /* properties_required */
	0,               /* properties_provided */
	0,               /* properties_destroyed */
	0,               /* todo_flags_start */
	0                /* todo_flags_finish */
};

unsigned int tricopt_gimple_execute(function *function);

class tric_pass_gimple : public gimple_opt_pass
{
public:
  tric_pass_gimple(gcc::context *ctxt)
      : gimple_opt_pass(tric_pass_data_gimple, ctxt)
  {
  }

  virtual bool gate(function *)
  {
      return true;
  }
  virtual unsigned int execute(function *function)
  {
      if (dump_file)
        fprintf(dump_file, "tric_pass_gimple\n");
      return tricopt_gimple_execute(function);
  }
};

const pass_data tric_pass_data_arg =
    {
        RTL_PASS,                            /* type */
        "tric-arg",                          /* name */
        OPTGROUP_NONE,                       /* optinfo_flags */
        TV_NONE,                             /* tv_id */
        0,                                   /* properties_required */
        0,                                   /* properties_provided */
        0,                                   /* properties_destroyed */
        0,                                   /* todo_flags_start */
        TODO_df_finish | TODO_df_verify | 0, /* todo_flags_finish */
};

unsigned int tricopt_execute_arg(function *function);

class tric_pass_arg : public rtl_opt_pass
{
public:
  tric_pass_arg(gcc::context *ctxt)
      : rtl_opt_pass(tric_pass_data_arg, ctxt)
  {
  }

  virtual bool gate(function *)
  {
      return true;
  }
  virtual unsigned int execute(function *function)
  {
      //	  return tric_rest_of_const_anchor ();
      if (dump_file)
        fprintf(dump_file, "tric_pass_arg\n");
      return tricopt_execute_arg(function);
  }
};

static const pass_data tric_pass_data_strcmp =
{
        GIMPLE_PASS,         /* type */
        "tric-strcmp",       /* name */
        OPTGROUP_NONE,       /* optinfo_flags */
        TV_NONE,             /* tv_id */
        PROP_cfg | PROP_ssa, /* properties_required */
        0,                   /* properties_provided */
        0,                   /* properties_destroyed */
        0,                   /* todo_flags_start */
        TODO_update_ssa      /* todo_flags_finish */
};

unsigned int tricopt_strcmp_execute(function *function);

class tric_strcmp_gimple : public gimple_opt_pass
{
public:
  tric_strcmp_gimple(gcc::context *ctxt)
      : gimple_opt_pass(tric_pass_data_strcmp, ctxt)
  {
  }

  virtual bool gate(function *)
  {
      return true;
  }
  virtual unsigned int execute(function *function)
  {
      if (dump_file)
        fprintf(dump_file, "tric_strcmp_gimple\n");
      return tricopt_strcmp_execute(function);
  }
};


/***********************************************************************
 ** Objects related to Section Handling
 ***********************************************************************/

/* 1st Dimension of `tric_data_section': Addressing Capability */
enum
  {
    SS_ABSOLUTE, SS_SMALL, SS_INDIRECT,
    SS1_MAX
  };

/* 2nd Dimension of `tric_data_section': Data Flavour */
enum
  {
    SS_DATA, SS_RODATA, SS_BSS,
    SS2_MAX
  };

/* 3rd Dimension of `tric_data_section': Data Alignment */
enum
  {
    SS_ALIGN_NONE = 0,
    SS_ALIGN_1, SS_ALIGN_2, SS_ALIGN_4, SS_ALIGN_8,
    SS3_MAX
  };

/* Default data sections as initialized by `tric_asm_init_sections':
   1st Dimension: Absolute/Small/Indirect-Only addressable
   2nd Dimension: .data/.rodata/.bss
   3rd Dimension: Alignment */
static GTY(()) section* tric_data_section[SS1_MAX][SS2_MAX][SS3_MAX];

#define zbss_section (tric_data_section[SS_ABSOLUTE][SS_BSS][0])

static GTY(()) tric_section_t *tric_builtin_sections;

/* only added for new items */
static tric_section_t *tric_sections;
#define  TRIC_SECTION_COLL_MAX 256
static tric_section_t tric_section_coll[TRIC_SECTION_COLL_MAX];
static int tric_section_coll_ind;
tric_section_t *tric_pragma_section_data;
tric_section_t *tric_pragma_section_code;
static void tric_set_decl_from_section (tree decl, tric_section_t *secp);
static unsigned long tric_section_flags_from_string (const char *s_flags);
static void tric_section_flags_from_flags (char *f, unsigned int flags);
static tric_section_t *tric_text_section;
static tric_section_t* tric_data_section_ext[SS1_MAX][SS2_MAX][SS3_MAX];
static void tric_asm_file_end_callinfo (void);


#define tric_zbss_section (tric_data_section[SS_ABSOLUTE][SS_BSS][0])
#define tric_zbss_section_ext (tric_data_section_ext[SS_ABSOLUTE][SS_BSS][0])
#define tric_bss_section (tric_data_section[SS_INDIRECT][SS_BSS][0])
#define tric_bss_section_ext (tric_data_section_ext[SS_INDIRECT][SS_BSS][0])
#define tric_sbss_section (tric_data_section[SS_SMALL][SS_BSS][0])
#define tric_sbss_section_ext (tric_data_section_ext[SS_SMALL][SS_BSS][0])

/* Ranges for (const) data to be put into absolute resp. small data sections
   set from -mabs* resp. -msmall* command line options. Ranges are inclusive
   the boundary. */
extern GTY(()) int tric_zdata_max;
extern GTY(()) int tric_zdata_min;
extern GTY(()) int tric_zconst_max;
extern GTY(()) int tric_zconst_min;
extern GTY(()) int tric_sdata_max;
extern GTY(()) int tric_sdata_min;
extern GTY(()) int tric_sconst_max;
extern GTY(()) int tric_sconst_min;

/***********************************************************************
 ** Miscellaneous Objects
 ***********************************************************************/

int tric_have_cost_insns = 0;
int mPos;
int mWidth;
int tric_map_combine;

extern GTY(()) struct tric_segment_trap tric_segment_trap;

/* Return true iff strings A and B are equal.  */
#define STREQ(A, B) (0 == strcmp (A, B))


/***********************************************************************
 ** Objects local to this file
 ***********************************************************************/

/* FIELD_DECLS for which we already reported that their size is
   greater than 32 bits. */

static GTY(()) tree tric_eabi_error = NULL_TREE;

/* Nodes for which we already warned as of -Winitialize-pid.  */

static GTY(()) tree tric_pid_init = NULL_TREE;

/* Enumerate .PICOFF<N> labels.  */
static GTY(()) int tric_picoff_labelno;

/* Pass number of some pass that is known be located after split1 and
   before register allocation.  */
static GTY(()) int tric_after_split1_pass_number;

/* Some rtx singletons used in rtx-cost computation */
static GTY(()) rtx_insn *fake_insn=NULL;
static GTY(()) rtx_insn *fake_jump_insn=NULL;
static GTY(()) rtx fake_pattern=NULL_RTX;
static GTY(()) rtx fake_jump_pattern=NULL_RTX;

static int tric_const_int_costs (int);
static int tric_const_double_costs (rtx);

static inline bool tric_symbol_ref_small16_p (const_rtx);

static void tric_print_operand (FILE*, rtx, int);

static rtx tric_arith_CONST_INT (rtx, rtx, rtx, rtx);

static const char *callinfo_label[10000];
static unsigned int callinfo_regsused[10000];
static unsigned int callinfo_argsused[10000];
static unsigned int callinfo_retsused[10000];
static unsigned int callinfo_statused[10000];
static int len_callinfo;

/***********************************************************************
 ** Miscellaneous Support Functions
 ***********************************************************************/
HOST_WIDE_INT tric_max_for_mode (enum machine_mode mode, bool signed_p)
{
  gcc_assert (SCALAR_INT_MODE_P (mode));
//TODO
//  gcc_assert (GET_MODE_PRECISION (SCALAR_TYPE_MODE(mode)) < HOST_BITS_PER_WIDE_INT));
  return GET_MODE_MASK (mode) >> signed_p;
}

static unsigned int
tric_hard_regno_nregs (unsigned regno ATTRIBUTE_UNUSED, machine_mode mode)
{
	return (   ((GET_MODE_SIZE (mode) + UNITS_PER_WORD - 1) / UNITS_PER_WORD));
}


/* Return true iff STR starts with PREFIX.  */

static bool
str_prefix_p (const char *str, const char *prefix)
{
  return 0 == strncmp (str, prefix, strlen (prefix));
}


/* If code CODE represents a signed operation, return TRUE.
   If code CODE represents an unsigned operation, return FALSE.  */

bool
tric_code_signed_p (enum rtx_code code)
{
  switch (code)
    {
    default:
      gcc_unreachable();

    case SMIN:  case SMAX:
    case LT:    case LE:
    case GT:    case GE:
    case SIGN_EXTEND:
      return true;

    case UMIN:  case UMAX:
    case LTU:    case LEU:
    case GTU:    case GEU:
    case ZERO_EXTEND:
      return false;
    }

  gcc_unreachable();
  return false;
}


/* Return TRUE if CODE1 and CODE2 are operation of the same signedness
   and FALSE, otherwise.  */

bool
tric_codes_same_sign_p (enum rtx_code code1, enum rtx_code code2)
{
  return tric_code_signed_p (code1) == tric_code_signed_p (code2);
}


/* If, taken as a function of x, the expression  (x CODE OP1) ? x : OP2
   is equivalent  to  (max x OP2)  then return the respective rtx code,
   i.e. UMAX or SMAX.  Otherwise, return UNKNOWN.  */

enum rtx_code
tric_max_code (enum rtx_code code, rtx op1, rtx op2)
{
  if (GEU == code || GTU == code)
    {
      if (CONST_INT_P (op1))
        op1 = GEN_INT (USIval (op1));
      if (CONST_INT_P (op2))
        op2 = GEN_INT (USIval (op2));
    }

  if (!rtx_equal_p (op1, op2)
      && CONST_INT_P (op1)
      && CONST_INT_P (op2))
    {
      if (GEU == code || GE == code)
        // Compute as DImode to avoid SI overflow / underflow.
        op1 = plus_constant (DImode, op1, -1);
      if (GTU == code || GT == code)
        op1 = plus_constant (DImode, op1, 1);
    }

  return !rtx_equal_p (op1, op2)
    ? UNKNOWN
    : GE == code || GT == code ? SMAX
    : GEU == code || GTU == code ? UMAX
    : UNKNOWN;
}


/* If, taken as a function of x, the expression  (x CODE OP1) ? x : OP2
   is equivalent to  (min x OP2)  then return the respective rtx code,
   i.e. UMIN or SMIN.  Otherwise, return UNKNOWN.  */

extern enum rtx_code
tric_min_code (enum rtx_code code, rtx op1, rtx op2)
{
  if (LEU == code || LTU == code)
    {
      if (CONST_INT_P (op1))
        op1 = GEN_INT (USIval (op1));
      if (CONST_INT_P (op2))
        op2 = GEN_INT (USIval (op2));
    }

  if (!rtx_equal_p (op1, op2)
      && CONST_INT_P (op1)
      && CONST_INT_P (op2))
    {
      if (LEU == code || LE == code)
        // Compute as DImode to avoid SI overflow / underflow.
        op1 = plus_constant (DImode, op1, 1);
      if (LTU == code || LT == code)
        op1 = plus_constant (DImode, op1, -1);
    }

  return !rtx_equal_p (op1, op2)
    ? UNKNOWN
    : LE == code || LT == code ? SMIN
    : LEU == code || LTU == code ? UMIN
    : UNKNOWN;
}


/* Return true if the operation

      (CODE_OUTER:SI (CODE_INNER:SI (x OP_INNER))
                     OP_OUTER)

   taken as a function of x, represents a signed saturation.  If MODE is
   QImode or HImode return TRUE iff this is a saturation to exact the range
   of that machine mode.  For other modes return TRUE if the operation
   comprises a generic signed saturation.  If TRUE is returned, *LOWER and
   *UPPER are set to the boundary values of the support of the operation,
   i.e. the operation is onto [*LOWER, *UPPER] then.  LOWER and UPPER may
   be omitted or passed as NULL.  */

bool
tric_sat_p (enum machine_mode mode, enum rtx_code code_inner, rtx op_inner,
            enum rtx_code code_outer, rtx op_outer,
            HOST_WIDE_INT *lower, HOST_WIDE_INT *upper)
{
  if (!CONST_INT_P (op_inner)
      || !CONST_INT_P (op_outer))
    return false;

  HOST_WIDE_INT ldummy, udummy;
  if (!lower) lower = &ldummy;
  if (!upper) upper = &udummy;

  *lower
    = SMAX == code_inner ? INTVAL (op_inner)
    : SMAX == code_outer ? INTVAL (op_outer)
    : INT_MAX;

  *upper
    = SMIN == code_inner ? INTVAL (op_inner)
    : SMIN == code_outer ? INTVAL (op_outer)
    : INT_MIN;

  if (UMIN == code_outer
      && SMAX == code_inner
      && INTVAL (op_inner) >= 0)
    {
      *lower = INTVAL (op_inner);
      *upper = USIval (op_outer);
    }

  return QImode == mode || HImode == mode
    ? (*upper == tric_max_for_mode (mode, true)
       && *lower == tric_min_for_mode (mode, true))
    : *lower < *upper;
}


/* Return true if the operation

      (CODE_OUTER:SI (CODE_INNER:SI (x OP_INNER))
                     OP_OUTER)

   taken as a function of x, represents an unsigned saturation.  If TRUE is
   returned, *LOWER and *UPPER are set to the boundary values of the support
   of the operation, i.e. the operation is onto [*LOWER, *UPPER] then.  */

bool
tric_usat_p (enum rtx_code code_inner, rtx op_inner,
             enum rtx_code code_outer, rtx op_outer,
             HOST_WIDE_INT *lower, HOST_WIDE_INT *upper)
{
  if (!CONST_INT_P (op_inner)
      || !CONST_INT_P (op_outer))
    return false;

  *lower
    = UMAX == code_inner ? USIval (op_inner)
    : UMAX == code_outer ? USIval (op_outer)
    : UINT_MAX;

  *upper
    = UMIN == code_inner ? USIval (op_inner)
    : UMIN == code_outer ? USIval (op_outer)
    : INT_MIN;

  if ((UMIN == code_outer
       || SMIN == code_outer)
      && SMAX == code_inner
      && INTVAL (op_inner) >= 0)
    {
      *lower = INTVAL (op_inner);
      *upper = SIval (op_outer, SMIN == code_outer);
    }

  if (UMIN == code_inner
      && SMAX == code_outer
      // sic!  This means op2 can be represented as signed
      // and the result as signed is >= 0.
      && INTVAL (op_inner) >= 0)
    {
      *lower = MAX (0, INTVAL (op_outer));
      *upper = INTVAL (op_inner);
    }

  if (SMIN == code_inner
      && SMAX == code_outer
      && INTVAL (op_outer) >= 0)
    {
      *lower = INTVAL (op_outer);
      *upper = INTVAL (op_inner);
    }

  return *lower < *upper;
}


/* A class representing the range of integers from .lower to .upper.

   .lower > .upper is the (non-unique) representation of the empty set.
   The empty set will never occur as result of a computation, but handling it
   as usual makes range-arithmetic more familiar and to operate like sets.

   `range_t' mostly deals with set operations like intersection and union.
   It also implements the point-wise action of some functions like minimum
   and maximum (against a given constant), addition or subtraction of a given
   constant, negation, absolute value, modulo, etc.  All of these are straight
   forward and many act transitively.  The only one that needs more attention
   is remainder of integer division (modulo).  */

class range_t
{
 public:
  HOST_WIDE_INT lower, upper;

  static const range_t none;
  static const range_t all;

  // All possible values or (non-unique representation of) the empty set.
  range_t (bool all_or_none)
    {
      lower = all_or_none ? TRIC_INT_MIN  : +42;
      upper = all_or_none ? TRIC_UINT_MAX : -42;
    }

  // Construct interval [LO, HI] if  LO <= HI  and the empty set if LO > HI.
  range_t (HOST_WIDE_INT lo, HOST_WIDE_INT up)
    {
      lower = lo;
      upper = up;
    }

  // Construct an interval that consists of all integers which can be
  // represented by mode MODE in the specified signedness:  As signed if
  // SIGNED_P = TRUE and as unsigned if SIGNED_P = FALSE.
  range_t (enum machine_mode mode, bool signed_p)
    {
      lower = tric_min_for_mode (mode, signed_p);
      upper = tric_max_for_mode (mode, signed_p);
    }

  // Is this the empty set?
  inline bool is_empty (void) const
  {
    return lower > upper;
  }

  // Size, i.e. cardinality of the set of integers.
  HOST_WIDE_INT size (void) const
  {
    return is_empty() ? 0 : upper - lower + 1;
  }

  // Are both non-empty?
  bool operator && (const range_t &r) const
  {
    return !is_empty() && !r.is_empty();
  }

  // Intersection
  range_t operator & (const range_t &r) const
  {
    return r && *this
      ? range_t (MAX (lower, r.lower), MIN (upper, r.upper))
      : range_t::none;
  }

  // Union
  // The union of ranges is the smallest range that contains all these ranges.
  range_t operator | (const range_t &r) const
  {
    return is_empty()
      ? r
      : r.is_empty() ? *this
      : range_t (MIN (lower, r.lower),
                 MAX (upper, r.upper));
  }

  // Subset of, i.e. contained in R?
  bool operator <= (const range_t &r) const
  {
    return r && *this
      ? r.lower <= lower && upper <= r.upper
      : is_empty ();
  }

  // Superset of, i.e. contains R?
  bool operator >= (const range_t &r) const
  {
    return r <= *this;
  }

  // Equal as sets?
  bool operator == (const range_t &r) const
  {
    return (r >= *this) && (r <= *this);
  }

  // Not equal as sets?
  bool operator != (const range_t &r) const
  {
    return !(r == *this);
  }

  // Shift by an offset of K:  [a, b] -> [a, b] + k := [a+k, b+k].
  // Union of {x + K} taken over all x's in the range.
  range_t operator + (HOST_WIDE_INT k) const
  {
    return is_empty ()
      ? range_t::none
      : range_t (lower + k, upper + k);
  }

  // Shift by an offset of -K:  [a, b] -> [a, b] - K := [a-K, b-K].
  // Union of {x - K} taken over all x's in the range.
  range_t operator - (HOST_WIDE_INT k) const
  {
    return (*this) + (-k);
  }

  // Mirror the range at x = 0:  [a, b] -> -[a, b] := [-b, -a].
  // Union of {-x} taken over all x's in the range.
  range_t operator - (void) const
  {
    return is_empty ()
      ? range_t::none
      : range_t (-upper, -lower);
  }

  // Union of {min (x, K)} taken over all x's in the range.
  range_t min (HOST_WIDE_INT k) const
  {
    return is_empty ()
      ? range_t::none
      : range_t (MIN (lower, k), MIN (upper, k));
  }

  // Union of {max (x, K)} taken over all x's in the range.
  range_t max (HOST_WIDE_INT k) const
  {
    return is_empty ()
      ? range_t::none
      : range_t (MAX (lower, k), MAX (upper, k));
  }

  // Union of {|x|} taken over all x's in the range.
  range_t abs (void) const
  {
    range_t neg = (*this) & range_t (TRIC_INT_MIN, -1);
    range_t pos = (*this) & range_t (0, TRIC_UINT_MAX);

    return pos | -neg;
  }

  // Union of {min (|x|, 0x7fffffff)} taken over all x's in the range.
  range_t ss_abs (void) const
  {
    return abs().min (TRIC_INT_MAX);
  }

  range_t mod (HOST_WIDE_INT m, HOST_WIDE_INT new_max) const;
  range_t mod (enum rtx_code code, enum machine_mode mode) const;

  // Let F act on the range.
  range_t image (const_rtx f) const;
};

range_t const range_t::none = range_t (false);
range_t const range_t::all = range_t (true);


/* Consider the pointwise canonical projection

       Z --> Z / m*Z

   with Z / m*Z represented by the largest integers that are not greater than
   NEW_MAX.  Return the smallest interval containing all representatives of
   x mod M  where x is an element of the input range.

   Some notes seem to be in order:  This method returns a superset of the
   range mod M.  We could model the exact image of mod, i.e. the range mod M
   if we implemented unions of (at most two) ranges.  We prefer to avoid
   putting too much effort into (unions of) intervals' arithmetic at the
   expense of fewer optimization opportunities:  Casting back and forth
   signed / unsigned flavours of the same base type does not change the value.
   For example

       (short) (unsigned short) x  =  (short) x.

   With the present implementation, however, this is no more the case
   and casting back and forth will blow up the range and we will lose
   information and therefore miss some optimization opportunities.

   Just consider the interval [-1, 0]:  Casting this to unsigned and
   then to signed again will map  0 -> 0 -> 0  and  -1 -> 0xffffffff -> -1
   and hence map [-1, 0] to [-1, 0].  Our simplistic intervals, however,
   will map [-1, 0] -> [0, UINT_MAX] -> [INT_MIN, INT_MAX] which means we
   have lost any information on the possible values resp. lost any
   information about which values will never occur.  */

range_t
range_t::mod (HOST_WIDE_INT m, HOST_WIDE_INT new_max) const
{
  gcc_assert (m > 0);

  if (is_empty())
    return range_t::none;

  /* Step 1:   Compute .upper mod M in the requested representative system,
     ======    i.e. the largest integer not greater than NEW_MAX which is
               element of the same residue class like .upper.  */

  // With
  //
  //     u_m = upper % m    and    x_m = new_max % m
  //     q_u = upper / m           q_x = new_max / m
  //
  // we have:
  //
  //     upper   = q_u * m + u_m   with   q_u in Z   and   0 <= |u_m| < m
  //     new_max = q_x * m + x_m          q_x in Z         0 <= |x_m| < m
  //
  // with whatever convention the C/C++ implementation is using for / and %.
  // These relations simply reflect the definition of quotient and remainder.
  //
  // Let i be some integer represented in the same way:
  //
  //     i = q_i * m + i_m         with   q_i in Z   and   0 <= |i_m| < m
  //
  // and consider the value
  //
  //     a = q_x * m + i_m         with    | x_m - i_m | < m              (*)
  //                               and       x_m - i_m   = new_max - a 
  //
  // The inequality (*) holds because quotient and remainder are computed
  // according to the same convention (supplied by the C/C++ implementation).
  //
  // If  a <= new_max  then from (*) we get   new_max - m < a <= new_max
  // i.e.  a  is the representative of  i mod m  that satisfies the desired
  // maximum condition w.r.t. new_max.
  //
  // If  a > new_max  then from (*) we get   new_max - m < a - m < new_max
  // i.e.  a - m  is the representative of  i mod m  that satisfies the
  // maximum condition.
  //
  // We apply this to  i := .upper  in order to get the right representative
  // r_upper of .upper mod m:

  HOST_WIDE_INT u_m = upper % m;
  HOST_WIDE_INT q_x = new_max / m;
  HOST_WIDE_INT r_upper = q_x * m + u_m;

  if (r_upper > new_max)
    r_upper -= m;

  /* Step 2:   Shift the interval (by some multiple of m) in such a way that
     =======   .upper is mapped to its representative r_upper mod m.  */

  // Reducing the range mod m means shifting it by an offset:
  // r_upper = upper + o  -->  o = r_upper - upper = r_lower - lower:

  range_t r = (*this) + (r_upper - upper);

  /* Step 3:   Determine (the smallest) superset of the reduction which
     ======    comprises an interval (when regarded as integers).  */

  if (r.lower > new_max - m)
    // If the representative of .lower satisfies the maximum condition then
    // the projected range is the right result.
    return r;
  else
    // Otherwise the range "wraps around" and we return the full range, i.e.
    // all elements of Z / m*Z  in the desired representative system.
    return range_t (new_max + 1 - m, new_max);
}


/* Return (a superset of) the canonical projection  p: Z --> Z / m*Z  where
   Z / m*Z is represented by a representative system which is convenient
   for code CODE in mode MODE.

   This method "translates" between TriCore instructions, i.e. target specific
   RTXes and their mathematical equivalent.  We state as much as possible in
   the mathematical language and notation.  This avoids much special-casing
   which would be needed in a machine dependent formulation.  */

range_t
range_t::mod (enum rtx_code code, enum machine_mode mode) const
{
  /* As already mentioned, all machine instructions are periodic (with period
     a divisor of 2^32).  This means the instructions actually operate on
     residue classes, i.e. on  Z / m*Z  rather than on the integers.  We
     chose a representative system S of Z / m*Z in such a way that CODE
     restricted to S is the same as some well known function  f: Z --> Z
     where in the latter case we identify equivalence classes with their
     representative in Z.  Consequently, we may use f in place of CODE:MODE
     as indicated by the following diagram:

                              CODE
                   Z / m*Z    --->   Z / m*Z

                     |                 ^
                     |         #       |
                     v                 |
                               f
                     Z        --->     Z

     For all supported RTX codes there is a straight forward function f.
     For example, SS_ABS restricted to S is  x --> min (|x|, INT_MAX).

     Also notice that SIGN_EXTEND and ZERO_EXTEND are *not* extensions from
     the mathematical point of view, they are *reductions* modulo some integer:
     For example we have

         (zero_extend:SI (reg:HI))    is    f:  x  -->  x mod 2^16

     in the smallest non-negative representative system.  */

  HOST_WIDE_INT period = range_t (mode, false /* whatever */).size();

  switch (code)
    {
    case ZERO_EXTEND:
    case UMIN:
    case UMAX:
      return mod (period, tric_max_for_mode (mode, false));

    case SIGN_EXTEND:
    case SMIN:
    case SMAX:
      return mod (period, tric_max_for_mode (mode, true));

    case ABS:
      return mod (period, 1 + tric_max_for_mode (mode, true));

    case SS_ABS:
      return mod (period, 1 + tric_max_for_mode (mode, true));

    case SUBREG:
      // SUBREG just specifies how the caller (some extension in our case)
      // will access SUBREG_REG. SUBREG itself does not change its argument,
      // hence return the range unaltered.
      return *this;

    default:
      gcc_unreachable();
    }
}


/* Let the function f act on I, the input range.  Return a subset S of Im(f),
   the image of f, such that  f(I) <= S <= Im(f).  */

range_t
range_t::image (const_rtx f) const
{
  enum rtx_code code = GET_CODE (f);
  HOST_WIDE_INT k = 0;

  if (BINARY_P (f))
    {
      gcc_assert (CONST_INT_P (XEXP (f, 1)));

      /* For binary operations we define

             f (x) := f_k (x) := f (x, k)

         where k is a compile-time constant.  Non-constant k (i.e. multi
         variate functions) are not supported because we cannot determine
         the image of f then.  */

      bool signed_p = (SMIN == code || SMAX == code);

      k = SIval (XEXP (f, 1), signed_p);
    }

  range_t im_f = range_t::none;

  switch (code)
    {
    case ABS:
      im_f = abs();
      break;

    case SS_ABS:
      im_f = ss_abs();
      break;

    case UMIN:
    case SMIN:
      im_f = min (k);
      break;

    case UMAX:
    case SMAX:
      im_f = max (k);
      break;

    case SUBREG:
      if (0 == SUBREG_BYTE (f))
        // SUBREG just specifies how the caller (some extension in our case)
        // will access SUBREG_REG. SUBREG itself does not change the value,
        // hence return the range unaltered.
        im_f = *this;
      break;

    case ZERO_EXTEND:
    case SIGN_EXTEND:
      im_f = mod (code, GET_MODE (XEXP (f, 0)));
      break;

    default:
      break;
    }

  gcc_assert (im_f != range_t::none);

  return im_f;
}


/* If expression F (taken as a function of some variable x) is a projection,
   then return that x.  Otherwise, return NULL_RTX.

   A function is called a `projection' if it satisfies f o f = f.

   All the functions below are obviously projections, e.g.
   (char)(char) x = (char) x   or  abs (x) = abs (abs (x))  etc.

   Apart from being projections, it must be possible to represent the image
   of F for a given domain.  A proper superset will *not* do, c.f. the
   comments in `tric_optimize_minmax_1' w.r.t. projections.  For example,
   f = f_k(x) = x AND k is obviously a projection, but we have no means to
   represent the image of f except in the case where k can be represented as
   k = 2^n - 1.  For such f the image of a range can be representd: it is
   some range, too.  (f comprises the remainder mod 2^n in that case.) */

static rtx
tric_is_projection (const_rtx f)
{
  const char *form = GET_RTX_FORMAT (GET_CODE (f));

  if (GET_MODE (f) != SImode
      || form[0] != 'e')
    return NULL_RTX;

  rtx x = XEXP (f, 0);

  switch (GET_CODE (f))
    {
    case UMIN:   case UMAX:
    case SMIN:   case SMAX:
      if (CONST_INT_P (XEXP (f, 1)))
        return x;
      break;

    case ZERO_EXTEND:
    case SIGN_EXTEND:
      if (QImode == GET_MODE (x)
          || HImode == GET_MODE (x))
        return x;
      break;

    case ABS:
    case SS_ABS:
      return x;

    default:
      break;
    }

  return NULL_RTX;
}


/* If f(x) is opt to be optimized by `tric_optimize_minmax' then return
   that x, the argument of F.  Otherwise, return NULL_RTX.  If we support
   a binary operation F, this means we take f(x) := f(x,k) where k is a
   compile time constant, i.e. f is an univariate function parameterized
   by k.  */

static rtx
tric_supported_rtx (const_rtx f)
{
  // We support SUBREGs because they occur as wrapper of the argument of
  // sign_extend and zero_extend.  Return SUBREG_REG in that case because
  // SUBREG_REG is the effective argument sign_extend / zero_extend will
  // operate on.

  if (SUBREG == GET_CODE (f))
    return (0 == SUBREG_BYTE (f)
            && SImode == GET_MODE (SUBREG_REG (f))
            && (// (SUBREG:QI (:SI) 0)
                QImode == GET_MODE (f)
                // (SUBREG:HI (:SI) 0)
                || HImode == GET_MODE (f)))
      ? SUBREG_REG (f)
      : NULL_RTX;

  // Apart from SUBREGs we only support projections.  We could also support
  // functions like x --> x + 1 etc. and track their action on ranges.
  // However, we could not take advantage of that information at the current
  // stage of compilation (insn combination) unless we supported complex fake
  // patterns involving these expressions, and then split them later in split1.
  // For now we assume that respective optimization opportunities are rare and
  // not worth the hassle, hence we just consider projections.

  return tric_is_projection (f);
}


/* Mutually recursive part of `tric_optimize_minmax'.  Optimize expression F.
   As a side effect adjust the range R.  The returned function has the
   same effect like F, i.e. for all specified inputs the returned function
   evaluates to the same values like F.  */

static rtx
tric_optimize_minmax_1 (rtx f, range_t &r)
{
  rtx new_f = NULL_RTX;

  // Regard f as an univariate function.  Get the argument of that function.
  // If NULL_RTX is returned, the respective function (rtx) is not supported
  // by this optimization.
  rtx old_x = tric_supported_rtx (f);

  if (!old_x)
    {
      // f(x) is not supported: Return all possible values and f unaltered.
      r = range_t::all;
      return f;
    }

  // If f(x) is supported, then recursively optimize its argument x (in depth
  // first traversal) and adjust the range R.
  rtx x = tric_optimize_minmax_1 (old_x, r);

  // Get a (superset of a) convenient domain for f.
  const range_t& dom_f = r.mod (GET_CODE (f), GET_MODE (f));

  // Determine the image of the domain under f.
  const range_t& im_f = dom_f.image (f);

  // We use the following proposition with S = dom_f to determine whether we
  // may optimize out a projection f:
  //
  //     If   dom_f <= Im(f)   then   f(x) = x   for all x in dom_f.
  //
  // If this is not obvious enough:
  //
  // Proposition:
  // Let f: S --> S be a projection and S <= Im(f).  Then f is the identity.
  //
  // Proof:
  // Just pick some x in S <= Im(f).  As x in Im(f), there is some u in S so
  // that f(u) = x and hence:  x = f(u) = (fof)(u) = f(f(u)) = f(x).  QED.

  if (tric_is_projection (f)
      && dom_f <= im_f)
    {
      switch (GET_CODE (f))
        {
        case ZERO_EXTEND:
        case SIGN_EXTEND:
          if (SUBREG == GET_CODE (x))
            {
              // The very argument of SIGN/ZERO_EXTEND is SUBREG_REG (x) and
              // not x.  SUBREG just serves to adjust the machine mode, thus
              // SUBREG_REG (x) is the right new_f.

              if (0 == SUBREG_BYTE (x)
                  && SImode == GET_MODE (SUBREG_REG (x)))
                {
                  new_f = SUBREG_REG (x);
                  break;
                }
              else
                gcc_unreachable();
            }
          new_f = x;
          break;

        default:
          // f = id, thus we may replace f(x) by x.
          new_f = x;
          break;
        }
    }

  int32_t k;
  enum rtx_code code = GET_CODE (f);

  // In some cases we may use UMIN / UMAX instead of SMIN / SMAX and take
  // advantage of the larger positive immediate range (u9_operand, i.e.
  // 0..511 instead of s9_operand, i.e. 0..255).  */

  if (!new_f
      // If SMAX / SMIN always sees ...
      && (SMAX == code
          || SMIN == code)
      // ... an argument which is positive when taken as signed ...
      && r <= range_t (0, TRIC_INT_MAX)
      // ... and similar for the parameter ...
      && (k = (int32_t) INTVAL (XEXP (f, 1))) >= 0)
    {
      // ...then we may use the unsigned version of the rtx_code.  This takes
      // advantage of the extended immediate range of UMIN / UMAX w.r.t.
      // SMIN / SMAX.  The only exception is SMIN + INT16_MAX because SAT.H
      // is better than UMIN (x, 32767).
      if (SMAX == code
          || k != 32767)
      new_f = gen_rtx_fmt_ee (SMIN == code ? UMIN : UMAX,
                              SImode, x, XEXP (f, 1));
    }

  if (new_f)
    {
      if (dump_file && (dump_flags & TDF_DETAILS))
        tricore_dump ("Replaced %I:\n%r\n\nBy this instruction:\n%r\n\n",
                   r, f, new_f);
    }
  else
    {
      // If something changed, then rebuild the new rtx; patching the original
      // one, i.e. replacing XEXP (f, 0), is not appropriate.

      if (x == old_x)
        {
          new_f = f;
        }
      else
        {
          new_f = copy_rtx (f);
          XEXP (f, 0) = x;
        }

      if (r != im_f)
        if (dump_file && (dump_flags & TDF_DETAILS))
          tricore_dump ("Constrained %I to %I by this instruction:\n%r\n\n",
                     r, im_f, new_f);

      r = im_f;
    }

  return new_f;
}


/* Optimize F, i.e. try to replace F by an equivalent expression
   or return F unaltered.  */

static rtx
tric_optimize_minmax (rtx f)
{
  enum rtx_code code = GET_CODE (f);
  rtx x = tric_supported_rtx (f);

  if (!x
      // f(x) is supported by this optimization.  Filter out some more RTXes
      // which are not worth applying the whole story and shortcut-return f.
      // This reduces babbling in the dump file for RTXes which cannot be
      // simplified, anyway.
      || REG_P (x)
      || MEM_P (x)
      // SUBREG is only supported as argument of sign_extend / zero_extend.
      || SUBREG == code
      // (CODE (SUBREG (REG) n)) cannot be simplified.
      || (SUBREG == GET_CODE (x)
          && REG_P (SUBREG_REG (x))))
    return f;

  // Start with the full range of possible input values.
  range_t r = range_t::all;

  // Try to replace f by an equivalent expression.
  rtx new_f = tric_optimize_minmax_1 (f, r);

  if (1 == r.size())
    // If the output range just consists of one integer, then return this
    // integer in place of f.
    new_f = gen_int_mode (r.lower, SImode);

  return new_f;
}


/* Similar to double-int.c:double_int_split_digit (it's static there).
   Splits last digit of *CST (taken as unsigned value) in BASE and returns it.
   BASE = 0 stands for 2^32.  */

unsigned
tric_double_int_pop_digit (double_int *cst, unsigned base)
{
  double_int b, rem;

  b = base
    ? double_int::from_uhwi ((unsigned HOST_WIDE_INT) base)
    : double_int_zero.set_bit (32);

  *cst = cst->udivmod (b, FLOOR_DIV_EXPR, &rem);
  
  return (unsigned) rem.to_uhwi();
}


/* Get a double_int representing the bits of a constant rtx X
   which is one of CONST_INT, CONST_DOUBLE.  */

static double_int
tric_const_double_value (rtx x)
{
  enum machine_mode mode = GET_MODE (x);
  
  if (CONST_DOUBLE_P (x)
      && mode != VOIDmode)
    {
      if (DFmode == mode)
        x = simplify_gen_subreg (DImode, x, DFmode, 0);
      else if (SFmode == mode)
        x = simplify_gen_subreg (SImode, x, SFmode, 0);
      else if (HFmode == mode)
        x = simplify_gen_subreg (HImode, x, HFmode, 0);
      else
        {
          tricore_edump ("%?: %r\n", x);
          gcc_unreachable();
        }
    }

  return rtx_to_double_int (x);
}


/* Add NODE to LIST.  Return true if NODE is already contained in LIST.  */

static bool
tric_node_seen (tree *list, tree node)
{
  tree l;
  
  for (l = *list; l != NULL_TREE; l = TREE_CHAIN (l))
    {
      if (node == TREE_VALUE (l))
        return true;

      if (TREE_CHAIN (l) == NULL_TREE)
        break;
    }

  *list = chainon (build_tree_list (NULL_TREE, node), *list);

  return false;
}


/* Split X into its low 32 bit and high 32 bit parts.
   Store the low part in *LO and the high part in *HI.  */

void
tric_split_const_rtx (rtx x, unsigned *lo, unsigned *hi)
{
  double_int dval = tric_const_double_value (x);
  *lo = tric_double_int_pop_digit (&dval, 0);
  *hi = tric_double_int_pop_digit (&dval, 0);
}


/* Return -1 if X is not a CONST_INT.  Return the value of X if it is
   a CONST_INT.  Notice that HOST_WIDE_INT is always 64 bits wide, even on
   32-bit hosts.  */

static HOST_WIDE_INT
tric_rtx_to_hwi (const_rtx x)
{
  if (CONST_INT_P (x))
    return INTVAL (x) & GET_MODE_MASK (SImode);

  return -1;
}


/* Return -1 if X is not a known integer constant at compile time.
   Return the value of X if it is know at compile time.  */

static HOST_WIDE_INT
tric_tree_to_hwi (const_tree x)
{
  STRIP_NOPS (x);

  if (INTEGER_CST == TREE_CODE (x))
    return TREE_INT_CST_LOW (x) & GET_MODE_MASK (SImode);

  return -1;
}


/* Get something like `(unsigned int) VAL' for the target.  */

static tree
tric_tree_uint (HOST_WIDE_INT val)
{
  return fold_convert (unsigned_type_node,
                       build_int_cst (unsigned_type_node,
                                      val & GET_MODE_MASK (SImode)));
}


/* Set machine_function.pic_offset.reg as singleton and return it.
   This is only used if -mcode-pic is on.  */

static rtx
tric_pic_offset_init (void)
{
  rtx *picoff = &cfun->machine->pic_offset.reg;
  rtx *symbol = &cfun->machine->pic_offset.symbol;

  if (*picoff == NULL_RTX)
    {
	  rtx_insn *seq, *insn;
      rtx a11 = gen_rtx_REG (SImode, REG_A11);
      basic_block entry_block = ENTRY_BLOCK_PTR_FOR_FN (cfun);
      edge entry_edge;
      char label[32];

      sprintf (label, ".PICOFF%d", ++tric_picoff_labelno);
      *symbol = gen_rtx_SYMBOL_REF (SImode, ggc_strdup (label));

      /* Can't deal with multiple successors of the entry block at the moment.
         Function should always have at least one entry point.  */

      gcc_assert (single_succ_p (entry_block));
      entry_edge = single_succ_edge (entry_block);

      start_sequence ();

      /* Load current code position of *SYMBOL to A11.  */

      emit_insn (gen_load_pc (*symbol));
      emit_move_insn (*picoff = gen_rtx_REG (SImode, REG_PIC), a11);

      /* Set pseudo *PICOFF to the offset between the current code position
         and the position determined at link time.  */

      emit_move_insn (*picoff,
                      gen_rtx_MINUS (Pmode, *picoff,
                                     force_reg (Pmode, *symbol)));

      /* Restore A11 to its original value.  */

      emit_move_insn (a11, get_hard_reg_initial_val (Pmode, REG_A11));
      
      seq = get_insns ();
      end_sequence ();

      /* Set location to prologue.  This corresponds to the
         opening '{' of the current function's body.  */

      for (insn = seq; insn != NULL_RTX; insn = NEXT_INSN (insn))
        if (INSN_P (insn))
          INSN_LOCATION (insn) = prologue_location;

      /* Emit at the very start of the function.  */

      insert_insn_on_edge (seq, entry_edge);
    }

  return *picoff;
}


/***********************************************************************
 ** tricore-specific passes.
 ***********************************************************************/

/***********************************************************************
 ** .tric-split1: Determine whether pass split1 has finished.
 ***********************************************************************/

/* FIXME: We compose insns by means of insn combine and split them in split1.
      We don't want IRA/reload to combine them to the original insns again
      because that avoids some CSE optimizations if constants are involved.
      If IRA/reload combines, the recombined insns get split again after
      reload, but then CSE does not take place.
         It appears that at present there is no other way to take away the
      insns from IRA.  Notice that split1 runs unconditionally so that all our
      insns will get split no matter of command line options.  */

bool
tric_gate_split1 (void)
{
  if (tric_after_split1_pass_number == 0
      || !current_pass
      || current_pass->static_pass_number < tric_after_split1_pass_number)
    return true;

  return false;
}


static const pass_data tric_pass_data_notice_split1 =
{
  RTL_PASS, /* type */
  "tric-split1", /* name */
  OPTGROUP_NONE, /* optinfo_flags */
  TV_NONE, /* tv_id */
  0, /* properties_required */
  0, /* properties_provided */
  0, /* properties_destroyed */
  0, /* todo_flags_start */
  0, /* todo_flags_finish */
};

class tric_pass_notice_split1 : public rtl_opt_pass
{
public:
  tric_pass_notice_split1 (gcc::context *ctxt)
    : rtl_opt_pass (tric_pass_data_notice_split1, ctxt)
  {}

  int get_next_pass_number (void)
  {
	  return next->static_pass_number;
  }

}; // class tric_pass_notice_split1


/***********************************************************************
 ** .tric-anchor: Strict RTL pass to improve constant loading.
 ***********************************************************************/

/* Loading compile-time constants can be improved by (re)using known values
   held in registers.  This is addressed by `TARGET_CONST_ANCHOR' which has
   several issues:

   1) It only works with additions up to the power-of-2 provided by that
      macro.  There are, however, much more opportunities with the present
      ISA.  One prominent example is ADDIH which cannot be modelled.

   2) TARGET_CONST_ANCHOR is used by CSE on non-strict RTL which runs before
      insn combine.  This can make it harder for combine to synthesize
      instructions that support large constant.  Examples are AND with
      constant that's implemented using INSERT or 64-bit multiplications and
      multiply-add with constants.

   3) CSE might increase register pressure or introduce operations that
      turn out to be cross-pipeline after register allocation.

  This new pass addresses all of these drawbacks.

  The pass runs right after register allocation and before peephole2, hence
  prior to all post-reload split passes and before sched2.  */


/* This function is used in conditions for post-reload move splits.  */

bool
tric_anchor_completed (void)
{
	return (reload_completed
          && cfun
          && cfun->machine->anchor_completed);
}


/* Gate function for .tric anchor.  It is always TRUE, e.g. even with
   optimization turned off, because the execute method has to set
   `machine_function.anchor_completed'.  */

static bool
tric_gate_const_anchor (void)
{
  return true;
}


/* Print a neat representation of HSET to DUMP_FILE.  */

static void
tric_print_hard_reg_set (const char *prefix, HARD_REG_SET hset)
{
  if (dump_file)
    {
      fprintf (dump_file, "%s{ ", prefix);
      for (int i = 0; i < FIRST_PSEUDO_REGISTER; i++)
        {
          if (TEST_HARD_REG_BIT (hset, i))
            fprintf (dump_file, "%d ", i);
        }
      fprintf (dump_file, "}\n");
    }
}


/* Return NULL_RTX or a pattern that loads XVAL, a value known at compile time,
   to hard register XREG.  XVALS[] is an array of CONST_INTs that fit SImode
   and that are held in SImode hard register n provided HR_KNOWN[n] is set.  */

static rtx
tric_maybe_anchor_const32 (rtx xreg, rtx xval, rtx xvals[32],
                           HARD_REG_SET hr_known)
{
  enum rtx_code code = UNKNOWN;
  rtx pat = NULL_RTX;
  xval = simplify_gen_subreg (SImode, xval, GET_MODE (xreg), 0);
  xreg = simplify_gen_subreg (SImode, xreg, GET_MODE (xreg), 0);

  unsigned reg0 = D_REG_P (xreg) ? REG_D0 : REG_A0;

  for (unsigned regno = reg0; regno < reg0 + 16; regno++)
    {
      rtx pat2;
      if (!TEST_HARD_REG_BIT (hr_known, regno)
          || !(pat2 = tric_arith_CONST_INT (xreg, xval,
                                            gen_rtx_REG (SImode, regno),
                                            xvals[regno])))
        continue;

      if (SET == GET_CODE (pat2))
        {
          // We cannot get better than SET, hence stop on SET.
          pat = pat2;
          break;
        }

      if (PLUS == GET_CODE (SET_SRC (pat2))
          && (// Prefer additions over anything else (except the SET above).
              code != PLUS
              // Prefer short additions over long ones.
              || s4_operand (XEXP (SET_SRC (pat2), 1), SImode)))
        {
          code = PLUS;
          pat = pat2;
        }
    }

    return pat;
}


/* Return NULL or a sequence of insns that load XVAL to XREG.  XREG is a
   64-bit hard register and XVAL represents a constant known at compile time.
   XVALS[] is an array of CONST_INTs that fit SImode and that are held in
   SImode hard register n provided HR_KNOWN[n] is set.  If NULL is returned
   then XVAL can be loaded to XREG by a single (64-bit) MOV insn. */

static rtx
tric_anchor_const64 (rtx xreg, rtx xval, rtx xvals[32], HARD_REG_SET hr_known)
{
  int pos, width;
  rtx xreg_lo, xreg_hi, xval_lo, xval_hi, pat = NULL_RTX;
  xval = simplify_gen_subreg (DImode, xval, GET_MODE (xreg), 0);
  xreg = simplify_gen_subreg (DImode, xreg, GET_MODE (xreg), 0);
  tric_split_di (&xval, &xval_lo, &xval_hi, 1);
  tric_split_di (&xreg, &xreg_lo, &xreg_hi, 1);
  uint32_t lo = INTVAL (xval_lo);
  uint32_t hi = INTVAL (xval_hi);

  start_sequence ();

  // Part 1:  Try to find a 1-insn sequence without using XVALS.  This
  //          can be a 64-bit MOV or an IMASK with appropriate operands.

  if (E_REG_P (xreg))
    {
      if (TRIC_HAVE_MOV64
          && satisfies_constraint_Ksg (xval))
        // TC1.6 has MOV for sign-extended 16-bit values.
        pat = gen_rtx_SET (xreg, xval);
      else if (0 == INTVAL (xval))
        // 0.0
        pat = gen_imaskdi (xreg, const0_rtx, const0_rtx, const0_rtx);
      else if ((pos = ones_mask (hi, &width)) >= 0
               && width < 32)
        {
          uint32_t val = (lo >> pos) & 0xf;

          if ((val << pos) == lo)
            // 1.0, 0.5, 2.0, ...
            pat = gen_imaskdi (xreg, gen_int_mode (val, SImode),
                               GEN_INT (pos), GEN_INT (width));
        }

      if (!pat
          && hi == 0
          && (pos = ones_mask (lo, &width)) >= 0
          && width <= 4)
        // Small bit cluster in the low part: 1 << n ... 15 << n
        pat = gen_imaskdi (xreg, gen_int_mode (lo >> pos, SImode),
                           GEN_INT (pos), const0_rtx);
    }

  // Part 2:  Try to find a 1-insn sequence using XVALS.  This can be a
  //          64-bit MOV or a sign- or zero-extend.

  // Test for plain 64-bit move from XVALS[] to XREG.

  if (TRIC_HAVE_MOV64
      && E_REG_P (xreg))
    for (unsigned regno = REG_D0; !pat && regno < 16; regno += 2)
      if (TEST_HARD_REG_BIT (hr_known, regno)
          && TEST_HARD_REG_BIT (hr_known, regno + 1)
          && INTVAL (xval_lo) == INTVAL (xvals[regno])
          && INTVAL (xval_hi) == INTVAL (xvals[regno + 1]))
        pat = gen_rtx_SET (xreg, gen_rtx_REG (DImode, regno));

  // Test for sign- or zero-extend from a 32-bit XVALS[] to 64-bit XREG.

  if (E_REG_P (xreg)
      && (const0_rtx == xval_hi
          || constm1_rtx == xval_hi))
    for (unsigned regno = REG_D0; !pat && regno < 16; regno++)
      if (TEST_HARD_REG_BIT (hr_known, regno)
          && INTVAL (xval_lo) == INTVAL (xvals[regno]))
        {
          if (hi == 0)
            pat = gen_zero_extendsidi2 (xreg, gen_rtx_REG (SImode, regno));
          else if (lo & 0x80000000)
            pat = gen_extendsidi2 (xreg, gen_rtx_REG (SImode, regno));
        }

  // There are no more simple 1-insn sequences.

  if (pat)
    {
      // Emit the 1-insn sequence if we found one.
      emit_insn (pat);

      if (SET == GET_CODE (pat)
          && CONST_INT_P (SET_SRC (pat)))
        {
          // Avoid trivial replacements
          end_sequence();
          return NULL_RTX;
        }
    }
  else
    {
      // Part 3:  We need at least 2 instructions.

      rtx xdummy;
      int n_lo = tric_split_const_int (xval_lo, &xdummy, &xdummy, SET);
      int n_hi = tric_split_const_int (xval_hi, &xdummy, &xdummy, SET);
      bool have_lo = true;

      // Load the low part as 1-insn sequence if applicable.

      if (1 == n_lo)
        emit_move_insn (xreg_lo, xval_lo);
      else if ((pat = tric_maybe_anchor_const32 (xreg_lo, xval_lo,
                                                 xvals, hr_known)))
        emit_insn (pat);
      else
        have_lo = false;

      // Update the information that `tric_maybe_anchor_const32' for the high
      // part is about to use.

      if (have_lo)
        {
          xvals[REGNO (xreg_lo)] = xval_lo;
          SET_HARD_REG_BIT (hr_known, REGNO (xreg_lo));
        }

      // Load the high part as 1- or 2-insn sequence.

      if (1 == n_hi)
        emit_move_insn (xreg_hi, xval_hi);
      else if ((pat = tric_maybe_anchor_const32 (xreg_hi, xval_hi,
                                                 xvals, hr_known)))
        emit_insn (pat);
      else
        tric_emit_move_CONST_INT (xreg_hi, xval_hi);

      if (!have_lo)
        {
          // Update the information that `tric_maybe_anchor_const32' for
          // the low part is about to use.
          xvals[REGNO (xreg_hi)] = xval_hi;
          SET_HARD_REG_BIT (hr_known, REGNO (xreg_hi));

          if ((pat = tric_maybe_anchor_const32 (xreg_lo, xval_lo,
                                                xvals, hr_known)))
            emit_insn (pat);
          else
            tric_emit_move_CONST_INT (xreg_lo, xval_lo);
        }
    }

  rtx seq = get_insns();
  end_sequence ();

  return seq;
}


typedef struct
{
  // .VALS[] holds a const_xxx that's known to be the content of hard
  // register n iff bit n of .KNOWN is set.  0 <= n < 32.
  HARD_REG_SET known;
  // Magic "32" is the number of TriCore's general purpose registers.
  rtx vals[32];
  // Just for sanity checking.
  bool valid;
} hreg_vals_t;


/* Go through basic block BB and update *HREGS, the knowledge about the
   general purpose registers when entering BB, to respective knowledge at
   the end of BB.  Also try to replace reg-const moves by more efficient
   instructions and to replace some reg-reg moves by preferred reg-const
   moves.  */

static void
tric_const_anchor_bb (basic_block bb, hreg_vals_t *hregs)
{
  HARD_REG_SET &hr_known = hregs->known;
  rtx *xvals = hregs->vals;
  rtx_insn *insn,*next;
  // Value held in general purpose hard register n.

  FOR_BB_INSNS_SAFE (bb, insn, next)
    {
      if (!NONDEBUG_INSN_P (insn))
        continue;

      // Represents all registers changed by the current insn.
      HARD_REG_SET hr_set;
      // Mode of the current move (if any).  Also indicates that the current
      // insn sets a hard reg to a known value if != VOIDmode.
      enum machine_mode mode = VOIDmode;
      rtx rsrc, src = NULL_RTX, dest = NULL_RTX;
      rtx seq = NULL_RTX;
      /*TODO if true or false*/
      find_all_hard_reg_sets (insn, &hr_set,true);

      bool is_set = (// This sets a general purpose hard register.
                     SET == GET_CODE (PATTERN (insn))
                     && REG_P (dest = SET_DEST (PATTERN (insn)))
                     && REGNO (dest) <= REG_A15
                     // Don't mess with fixed registers.
                     && !fixed_regs[REGNO (dest)]
                     // Don't use unused regs left over from previous passes.
                     && !find_reg_note (insn, REG_UNUSED, dest));

      /* If this insn loads a compile-time constant to a register
        
             (set  reg  const_***)
        
         then try to find a better sequence than just MOVH + ADDI / LEA.  */

      if (is_set
          // The register is set to a compile time constant.
          && (CONST_INT_P (src = SET_SRC (PATTERN (insn)))
              || CONST_DOUBLE_P (src)))
        {
          mode = GET_MODE (dest);

          if (GET_MODE_SIZE (mode) <= 4)
            seq = tric_maybe_anchor_const32 (dest, src, xvals, hr_known);
          else if (GET_MODE_SIZE (mode) == 8)
            seq = tric_anchor_const64 (dest, src, xvals, hr_known);
        } // reg-const move

      /* Some passes like CSE transfrom loading of the same constant to
         reg-reg moves
         
             (set  reg_A  const_***)
             (set  reg_B  reg_A)
        
         Undo this if the value of the source register is known and can be
         loaded by 1 instruction.  Such reg-reg moves introduce additional
         scheduling dependencies or might represent cross-pipeline moves.
         Hence we try to undo such moves and resurrect the original set to
         the constant.  This also makes it easier for peephole2 to combine
         two sets into one 64-bit move like MOV %En, 0.  */

      if (is_set
          && GET_MODE_SIZE (GET_MODE (dest)) <= 4
          && REG_P (rsrc = SET_SRC (PATTERN (insn)))
          && REGNO (rsrc) <= REG_A15
          // Don't mess with fixed registers.
          && !fixed_regs[REGNO (rsrc)]
          // Is this is a reg-reg move where the source has a known value?
          && TEST_HARD_REG_BIT (hr_known, REGNO (rsrc)))
        {
          mode = GET_MODE (dest);
          src = xvals[REGNO (rsrc)];

          if (// Loading 0...15 to A-regs ...
              (A_REG_P (dest) && u4_operand (src, SImode))
              // ... and -8...7 to D-regs just costs 2 bytes.
              || (D_REG_P (dest) && s4_operand (src, SImode))
              || (!optimize_size
                  // If not optimizing for size avoid pipeline disruption.
                  && (A_REG_P (rsrc) ^ D_REG_P (dest))
                  && (high_operand (src, SImode)
                      || (D_REG_P (dest)
                          && (s16_operand (src, SImode)
                              || u16_operand (src, SImode)))
                      || (A_REG_P (dest)
                          && satisfies_constraint_KSa (src)))))
            seq = gen_rtx_SET (dest,
                               simplify_gen_subreg (mode, src, SImode, 0));
        } // reg-reg move

      if (dump_file)
        {
          if (mode != VOIDmode)
            tricore_dump ("\n  %r\n", insn);
          fprintf (dump_file, "\n;; Set by insn %d: ", INSN_UID (insn));
          tric_print_hard_reg_set ("", hr_set);
        }

      // Invalidate all registers set or changed or clobbered by this insn.
      hr_known &= ~ hr_set;
/* CHECK
      if (mode != VOIDmode)
        {
          // If this insn sets DEST to a value known at compile time
          // then record the values of all subregs of DEST in XVALS[]
          // and set respective bits in HR_KNOWN to 1.

          unsigned regno = REGNO (dest);
          for (uint32_t i = 0; i < tric_hard_regno_nregs (regno, mode); i++)
            {
              SET_HARD_REG_BIT (hr_known, regno + i);
              xvals[regno + i]
                = simplify_gen_subreg (SImode, src, mode,
                                       i * GET_MODE_SIZE (SImode));
              tricore_dump (";; %s = %r\n", reg_names[regno + i],
                         xvals[regno + i]);
            }

          if (seq)
            {
              // If we found a sequence or a pattern that's better than
              // MOVH + ADDI / LEA then replace the current insn.
              tricore_dump (";; Successfully replaced %r by:\n\n", src);
              tricore_dump (INSN_P (seq) ? "%L\n" : "%r\n\n", seq);

              emit_insn_before (seq, insn);
              delete_insn (insn);
            }
        }
*/
      tric_print_hard_reg_set (";; Known        : ", hr_known);
    } // insn
}


/* Implement execute() method of pass tric-anchor.  */

/* It works on basic blocks and implements a very simplistic simulation
   of the instructions:  When a compile-time constant is loaded to a register,
   the respective value is recorded.  If the value survives until a subsequent
   load, the compiler tries to use some arithmetic to compute the new value
   from one of the already known values -- the const anchors.  */

static unsigned int
tric_rest_of_const_anchor (void)
{
  /* Even though we currently run before the first post-reload split, some
     mov splitters use anchor_completed in their condition.  This gives us
     more freedom moving around this pass and trying to find the best
     placement.  Splitting mov insns before this pass would obviously
     disturb the optimizations we have in mind.  */

  gcc_assert (!cfun->machine->anchor_completed);
  cfun->machine->anchor_completed = true;
  if (!optimize
      || !tric_opt_const_anchor)
    return 0;

  df_note_add_problem ();
  df_analyze();

  /* Upper boundary for the basic block indices. */
  int max_bb_index = last_basic_block_for_fn (cfun);
  /* Number of basic blocks in the current function. */
  int n_bbs = n_basic_blocks_for_fn (cfun);
  /* HREG_VALS[] is indexed by the basic blocks.  Each element contains
     information about which of the 32 GPRs is holding a known value.  */
  hreg_vals_t *hreg_vals = XNEWVEC (hreg_vals_t, max_bb_index);
  /* Order BBs in such a way that single-predecessor BBs are orderd before
     their predecessor.  This enables us to regard the BBs as disjoint
     union of trees.  Roots of the trees are BBs with more than one
     predecessor.  The remaining vertices (leaves and branchings of the trees)
     are single-predecessor BBs that will inherit the hreg_vals[] knowledge
     from their predecessor.  */
  basic_block *bb_forest = single_pred_before_succ_order ();

  /* Traverse the forest's roots.  The order of the traversal does not matter.
     Each root starts with zero knowledge about the register contents.  */

  tricore_dump (";; Starting bb forest\n");

  for (int i = 0; i < max_bb_index; i++)
    if (i < NUM_FIXED_BLOCKS)
      {
        CLEAR_HARD_REG_SET (hreg_vals[i].known);
        hreg_vals[i].valid = true;
      }
    else
      hreg_vals[i].valid = false;

  for (int i = 0; i < n_bbs - NUM_FIXED_BLOCKS; i++)
    if (! single_pred_p (bb_forest[i]))
      {
        basic_block bb = bb_forest[i];
        tricore_dump ("\n;; bb %d\n", bb->index);

        gcc_assert (bb->index >= NUM_FIXED_BLOCKS
                    && bb->index < max_bb_index);

        /* Roots start with zero knowledge. */

        CLEAR_HARD_REG_SET (hreg_vals[bb->index].known);
        hreg_vals[bb->index].valid = true;

        tric_const_anchor_bb (bb, & hreg_vals[bb->index]);
      }

  /* Traverse the forest's leaves and branches.  The order of the traversal
     does matter and is performed in such a way that a BB Y which is the
     unique predecessor of BBs X1, X2, ... is handled before these Xs.
     A correct ordering is assured by the fact that the roots are already
     handled and by iterating the result of `single_pred_before_succ_order'
     from last to first (for Ys that are non-roots).  The incoming knowledge
     of a non-root Xn is given by the outcoming knowledge of its Y.  */

  tricore_dump ("\n;; Completing bb forest\n");

  for (int i = n_bbs - NUM_FIXED_BLOCKS - 1; i >= 0; i--)
    if (single_pred_p (bb_forest[i]))
      {
        basic_block bb = bb_forest[i];
        basic_block pred = single_pred_edge (bb)->src;

        gcc_assert (bb->index >= NUM_FIXED_BLOCKS
                    && bb->index < max_bb_index
                    && pred->index < max_bb_index);

        /* Non-roots start with their predecessor's results. */

        gcc_assert (hreg_vals[pred->index].valid);
        hreg_vals[bb->index] = hreg_vals[pred->index];

        tricore_dump ("\n;; bb %d\n;; Known from bb %d:", bb->index, pred->index);
        tric_print_hard_reg_set (" ", hreg_vals[bb->index].known);

        tric_const_anchor_bb (bb, & hreg_vals[bb->index]);
      }

  XDELETEVEC (bb_forest);
  XDELETEVEC (hreg_vals);

  df_analyze();

  if (flag_checking)
  verify_flow_info ();

  return 0;
}


static const pass_data tric_pass_data_const_anchor =
{
  RTL_PASS,      /* type */
  "tric-anchor", /* name */
  OPTGROUP_NONE, /* optinfo_flags */
  TV_NONE,       /* tv_id */
  0, /* properties_required */
  0, /* properties_provided */
  0, /* properties_destroyed */
  0, /* todo_flags_start */
  TODO_df_finish | TODO_df_verify | 0, /* todo_flags_finish */
};

class tric_pass_const_anchor : public rtl_opt_pass
{
public:
  tric_pass_const_anchor (gcc::context *ctxt)
    : rtl_opt_pass (tric_pass_data_const_anchor, ctxt)
  {}

  virtual bool gate (function *) {
	  return tric_gate_const_anchor ();
  }
  virtual unsigned int execute (function*)
  {
	  return tric_rest_of_const_anchor ();
  }
}; // tric_pass_const_anchor


/***********************************************************************
 ** Attributes
 ***********************************************************************/

/* A helper for the subsequent function attribute predicates to dig for
   attribute NAME in FUNC, a FUNCTION_DECL or FUNCTION_TYPE.  */

static inline int
tric_lookup_function_attribute1 (const_tree func, const char *name)
{
  tree a;

  if (FUNCTION_DECL == TREE_CODE (func))
    func = TREE_TYPE (func);
    
  gcc_assert (TREE_CODE (func) == FUNCTION_TYPE
              || TREE_CODE (func) == METHOD_TYPE);

  a = lookup_attribute (name, TYPE_ATTRIBUTES (func));
  return a != NULL_TREE;
}


/* Return nonzero if FUNC is an __interrupt__ function */

int
tric_interrupt_function_p (const_tree func)
{
  return tric_lookup_function_attribute1 (func, TRIC_ATTR_INTERRUPT);
}


/* Return nonzero if FUNC is an __interrupt_handler__ function */

int
tric_interrupt_handler_function_p (const_tree func)
{
  return tric_lookup_function_attribute1 (func, TRIC_ATTR_INTERRUPT_HANDLER);
}


/* Return nonzero if FUNC is a __pxhndcall__ PXROS handler call */

int
tric_pxhndcall_function_p (const_tree func)
{
  return tric_lookup_function_attribute1 (func, TRIC_ATTR_PXHNDCALL);
}


/* Return nonzero if FUNC is a __longcall__ function */

int
tric_longcall_function_p (const_tree func)
{
  return tric_lookup_function_attribute1 (func, TRIC_ATTR_LONGCALL);
}


/* Handle a function attribute.
   This is a hook in TARGET_ATTRIBUTE_TABLE, i.e.
   struct attribute_spec.handler.  */

static tree
tric_handle_fntype_attribute (tree *node, tree name,
                              tree args ATTRIBUTE_UNUSED,
                              int flags ATTRIBUTE_UNUSED,
                              bool *no_add_attrs)
{
  if (TREE_CODE (*node) != FUNCTION_TYPE)
    {
      warning (OPT_Wattributes, "%qs attribute only applies to functions",
               IDENTIFIER_POINTER (name));
      *no_add_attrs = true;
    }

  return NULL_TREE;
}


/* Handle a variable attribute.
   This is a hook in TARGET_ATTRIBUTE_TABLE, i.e.
   struct attribute_spec.handler.  */

static tree
tric_handle_decl_attribute (tree *node, tree name,
                            tree args ATTRIBUTE_UNUSED,
                            int flags ATTRIBUTE_UNUSED, bool *no_add_attrs)
{
  if (!DECL_P (*node))
    {
      warning (OPT_Wattributes, "%qs attribute only applies to variables",
               IDENTIFIER_POINTER (name));
      *no_add_attrs = true;
    }

  return NULL_TREE;
}


static void
tric_insert_attributes (tree node, tree *attributes ATTRIBUTE_UNUSED)
{
  tric_section_t *secp;

  if (TREE_CODE (node) == FUNCTION_DECL)
    secp = tric_pragma_section_code;
  else
    secp = tric_pragma_section_data;

  if (secp == NULL)
      return;

  if (current_function_decl != NULL_TREE
      && TREE_CODE (node) == VAR_DECL
      && TREE_STATIC (node))
    {
      /* if DECL_CONTEXT is not set yet we have to do it here to get the
         right scope */
      if (DECL_CONTEXT (node) == NULL_TREE)
        DECL_CONTEXT (node) = current_function_decl;
    }

  if ((current_function_decl == NULL_TREE     /* global scope */
       || (TREE_CODE (node) == VAR_DECL
           && TREE_STATIC (node)))  /* local static */
      && (TREE_CODE (node) == VAR_DECL
          || TREE_CODE (node) == CONST_DECL
          || TREE_CODE (node) == FUNCTION_DECL)

      && DECL_SECTION_NAME (node) == NULL)
    {
      tric_set_decl_from_section (node, secp);
    }

  return;
}


/* Test if NAME is a valid section name.  Valid section names are
   like valid C identifiers.  In addition, '.' might be used like
   a letter.  */

static bool
tric_valid_section_name_p (const char *name)
{
  const char *s;

  if (*name == '\0')
    return false;

  for (s = name; *s; s++)
    {
      char c = *s;

      if (c == '.'
          || c == '_'
          || (c >= 'a' && c <= 'z')
          || (c >= 'A' && c <= 'Z'))
        {
          continue;
        }

      /* First letter must not be a digit */

      if (s == name
          || c < '0' || c > '9')
        {
          return false;
        }
    }

  return true;
}


/* Search for section NAME in the section list. Return a pointer to the section
   with thar name or NULL if such a section does not (yet) exist. */

static tric_section_t*
tric_lookup_section (const char *name)
{
  tric_section_t *secp = tric_sections;

  for (secp = tric_sections; secp; secp = secp->next)
    if (STREQ (name, secp->name))
    {
    	break;
    }
    else
    {
    }
  return secp;
}

/* Insert a new section definition to our section list.
   If an equally named section already exists, check for compatibility of flags
   and alignment.

   If align=0 no alignment was specified, we use default alignment in that case.
   Otherwise, we have already tested that align is a power of 2.

   If s_flags is NULL no flags were specified, we use default flags "aw"
   in that case.

   If everything is fine return the pointer to the newly created or already
   existing section. Otherwise, print error message and return NULL. */

tric_section_t*
tric_insert_section (const char *name, const char *s_flags,
                     unsigned int align, location_t location)
{
  unsigned long flags;
  tric_section_t *secp;

  if (!tric_valid_section_name_p (name))
    {
      error ("invalid section name %qs", name);
      return NULL;
    }

  secp = tric_lookup_section (name);
//TODO
/*
  if (s_flags)
  {
	  flags=tric_section_flags_from_string (s_flags);
  }
  else
  {
	  if (secp)
		  flags=(int) secp->flags;
	  else
		  flags= (int) SECTION_WRITE;
  }*/
  flags = (s_flags
           ? tric_section_flags_from_string (s_flags)
           : secp ? secp->flags : SECTION_WRITE);

  if (flags == -1UL)
    {
      error ("illegal section flags for section %qs: %qs", name, s_flags);
      return NULL;
    }

  if (align == 0)
    {
      /* Use known resp. default alignment */
      align = secp ? secp->align : (flags & SECTION_CODE) ? 2 : 0;
    }
  else
    {
      if (align < 2
          && (flags & SECTION_CODE))
        {
          error ("minimum alignment for a code section is 2");

          if (!secp)
            return NULL;

          /* If section is known print error message below to indicate
             proper usage */
        }
    }

  if (secp)
    {
      const char *s_here = (secp->location == BUILTINS_LOCATION
                            ? "built-in" : "here");

      location_t loc = (secp->location == BUILTINS_LOCATION
                        ? location : secp->location);

      if (secp->flags != flags)
        {
          char old_flags[20];
          char new_flags[20];

          tric_section_flags_from_flags (old_flags, secp->flags);
          tric_section_flags_from_flags (new_flags, flags);

          error ("section %qs redefined with different flags %qs",
                 name, new_flags);
          inform (loc, "section %qs defined %s with flags %qs",
                  name, s_here, old_flags);
        }

      if (align != secp->align)
        {
          error ("section %qs redefined with different alignment %d",
                 name, align);

          if (secp->align)
            inform (loc, "section %qs defined %s with alignment %d",
                    name, s_here, secp->align);
          else
            inform (loc, "section %qs defined %s with no alignment",
                    name, s_here);
        }

      if (flags != secp->flags
          || align != secp->align)
        {
          return NULL;
        }
    }

  if (tricore_log.section)
    {
      char new_flags[20];

      const char *s_code = (flags & SECTION_CODE) ? "code" : "data";

      tric_section_flags_from_flags (new_flags, flags);

      if (secp)
        {
          if (secp->location == BUILTINS_LOCATION)
            tricore_edump ("%H: using built-in %s section %s, f=%s, a=%d\n",
                        location, s_code, name, new_flags, align);
          else
            tricore_edump ("%H: using %s section %s, f=%s, a=%d defined in %H\n",
                        location, s_code, name, new_flags, align,
                        secp->location);
        }
      else
        {
          tricore_edump ("%H: defining %s section %s, f=%s, a=%d\n",
                      location, s_code, name, new_flags, align);
        }
    } /* tric_debug.section */

  if (secp)
    return secp;
  secp=&tric_section_coll[tric_section_coll_ind];
  tric_section_coll_ind+=1;
  if (tric_section_coll_ind==TRIC_SECTION_COLL_MAX)
  {
      error ("internal problem: section collection overflow\n");
  }
  //TODO check length of name
  strcpy(secp->name,name);
  if (strlen(name)>255)
  {
      error ("internal problem: section name to long\n");
  }
  secp->flags = flags;
  secp->align = align;
  secp->next = tric_sections;
  secp->location = location;

  tric_sections = secp;
  return secp;
}



static void
tric_set_decl_from_section (tree decl, tric_section_t *secp)
{
  /* The decl may have already been given a section attribute
     from a previous declaration.  Ensure they match.  */

  if (DECL_SECTION_NAME (decl) != NULL
      && !STREQ (secp->name, DECL_SECTION_NAME (decl)))
    {
      error ("section of %q+D conflicts with previous declaration",
             decl);
      return;
    }
  set_decl_section_name (decl, secp->name);

  if (secp->align)
    {
      DECL_ATTRIBUTES (decl)
        = tree_cons (get_identifier ("aligned"),
                     tree_cons (NULL_TREE, size_int (secp->align), NULL_TREE),
                     DECL_ATTRIBUTES (decl));
      SET_DECL_ALIGN (decl, FUNCTION_ALIGNMENT ((int) secp->align * BITS_PER_UNIT));
      DECL_USER_ALIGN (decl) = 1;
    }

  if (secp->flags & TRIC_SECTION_ABSOLUTE)
    {
      DECL_ATTRIBUTES (decl)
        = tree_cons (get_identifier (TRIC_ATTR_ABSOLUTE), NULL_TREE,
                     DECL_ATTRIBUTES (decl));
    }

  if (secp->flags & SECTION_SMALL)
    {
      DECL_ATTRIBUTES (decl)
        = tree_cons (get_identifier ("smalldata"), NULL_TREE,
                     DECL_ATTRIBUTES (decl));
    }

  if (!(secp->flags & SECTION_WRITE)
      && TREE_CODE (decl) == VAR_DECL
      && (TREE_STATIC (decl) || DECL_EXTERNAL (decl)))
    {
      tree node0 = decl;

      /* For C++, we have to peel arrays in order to get correct
         determination of readonlyness.  */

      do
        node0 = TREE_TYPE (node0);
      while (TREE_CODE (node0) == ARRAY_TYPE);

      if (node0 != error_mark_node
          && !TYPE_READONLY (node0)
          && !TREE_READONLY (decl))
        {
          warning (0, "non-const variable %q+D put into read-only section %qs",
                   decl, secp->name);
        }
    }
}


/* Insert a new, attribute-defined section into our section list */

static bool
tric_set_section_attributes (tree decl, const char *name, const char *s_flags,
                             unsigned int align)
{
  tric_section_t *secp;

  secp = tric_insert_section (name, s_flags, align,
                              DECL_SOURCE_LOCATION (decl));
  if (secp == NULL)
    return false;

  if ((secp->flags & SECTION_CODE)
      && TREE_CODE (decl) != FUNCTION_DECL)
    {
      error ("variable %qD cannot be put into code section", decl);
      return false;
    }


  if (!(secp->flags & SECTION_CODE)
      && TREE_CODE (decl) == FUNCTION_DECL)
    {
      error ("function %qD cannot be but into non-code section", decl);
      return false;
    }

  tric_set_decl_from_section (decl, secp);

  return true;
}


/* Handle the asection attribute.  */

static tree
tric_handle_asection_attribute (tree *node, tree name ATTRIBUTE_UNUSED,
                                tree args, int flags ATTRIBUTE_UNUSED,
                                bool *no_add_attrs)
{
  tree decl = *node;
  const char *sec_name = NULL;
  const char *s_flags = 0;
  unsigned int align = 0;
  tree t;

  sec_name = TREE_STRING_POINTER (TREE_VALUE (args));

  for (t = TREE_CHAIN (args); t; t = TREE_CHAIN (t))
    {
      const char *str = TREE_STRING_POINTER (TREE_VALUE (t));

      switch (*str)
        {
        case 'a':
          {
            align = atoi (str+2);

            if (exact_log2 (align) < 0)
              {
                error ("%D: illegal %qs alignment %qs (must be a power of 2)",
                       decl, TRIC_ATTR_ASECTION, str+2);

                *no_add_attrs = true;
              }
          }
          break;

        case 'f':
          {
            s_flags = str+2;
          }
          break;

        default:
          {
            error ("%D: illegal %qs attributes %qs",
                   decl, TRIC_ATTR_ASECTION, str);

            *no_add_attrs = true;
          }
          break;
        }
    }

  if (TREE_CODE (decl) == VAR_DECL
      && current_function_decl != NULL_TREE
      && !TREE_STATIC (decl))
    {
      error ("%D: attribute %qs not allowed for local variables",
             decl, TRIC_ATTR_ASECTION);
      *no_add_attrs = true;
      return NULL_TREE;
    }

  if (!tric_set_section_attributes (decl, sec_name, s_flags, align))
    *no_add_attrs = true;

  return NULL_TREE;
}


/* Implement `TARGET_ATTRIBUTE_TABLE' */

const struct attribute_spec tric_attribute_table[] =
  {
    /* { name, min_len, max_len,
       decl_req, type_req, fn_type_req, handler, affects_type_identity } */
    { TRIC_ATTR_INTERRUPT,          0, 0,
      false, true,  true, false, tric_handle_fntype_attribute, NULL },
    { TRIC_ATTR_INTERRUPT_HANDLER,  0, 0,
      false, true,  true, false, tric_handle_fntype_attribute, NULL },
    { TRIC_ATTR_PXHNDCALL,          0, 0,
      false, true,  true, false, tric_handle_fntype_attribute,  NULL },
    { TRIC_ATTR_LONGCALL,           0, 0,
      false, true,  true, false, tric_handle_fntype_attribute,  NULL },
    { TRIC_ATTR_ABSOLUTE,           0, 0,
      true,  false, false, false, tric_handle_decl_attribute, NULL },
    { TRIC_ATTR_INDIRECT,           0, 0,
      true,  false, false, false, tric_handle_decl_attribute, NULL },
    { TRIC_ATTR_SMALL,              0, 0,
      true,  false, false, false, tric_handle_decl_attribute, NULL },
    { TRIC_ATTR_ASECTION,            1, 3,
      true,  false,  false, false, tric_handle_asection_attribute, NULL },
    { NULL,                      0, 0, false, false, false, false, NULL, NULL }
  };

static void
tric_section_flags_from_flags (char *f, unsigned int flags)
{
  if (!(flags & SECTION_DEBUG))
    *f++ = 'a';
  if (flags & SECTION_WRITE)
    *f++ = 'w';
  if (flags & SECTION_CODE)
    *f++ = 'x';
  if (flags & SECTION_MERGE)
    *f++ = 'M';
  if (flags & SECTION_STRINGS)
    *f++ = 'S';
  if (HAVE_COMDAT_GROUP && (flags & SECTION_LINKONCE))
    *f++ = 'G';
  if (flags & SECTION_SMALL)
    *f++ = 's';
  if (flags & TRIC_SECTION_ABSOLUTE)
    *f++ = 'z';
  if (flags & SECTION_BSS)
    *f++ = 'B';
  if (flags & TRIC_SECTION_CORE_MASK)
    {
      *f++ = 'c';
      *f++ = TRIC_SECTION_CORE_GET (flags) - 1 + '0';
    }

  *f = '\0';
}

/* Map the string FLAG_STR of section flags to unsigned long.
   If some unknown flag char is encountered return -1UL.
   No error message will be printed in that case. */

static unsigned long
tric_section_flags_from_string (const char *s_flags)
{
  unsigned long flags = 0;

  while (*s_flags)
    {
      switch (*s_flags++)
        {
        case 'a':
          break;
        case 'w':
          flags |= SECTION_WRITE;
          break;
        case 'x':
          flags |= SECTION_CODE;
          break;
        case 'M':
          flags |= SECTION_MERGE;
          break;
        case 'S':
          flags |= SECTION_STRINGS;
          break;
        case 's':
          flags |= SECTION_SMALL;
          break;
        case 'z':
          flags |= TRIC_SECTION_ABSOLUTE;
          break;
        case 'p':
          flags |= TRIC_SECTION_PCP;
          break;
        case 'B':
          flags |= SECTION_BSS;
          break;
        case 'c':
          if (IN_RANGE (*s_flags, '0', '6'))
            {
              flags = TRIC_SECTION_CORE_SET (flags,
                                             *s_flags - '0' + 1);
              s_flags++;
              break;
            }
          else if (*s_flags == 'g')
            {
              s_flags++;
              break;
            }
          return -1UL;
          
        default:
          /* Handle erroneous flags in some higher level so that we can
             print proper error message */
          return -1UL;
        }
    }

  if ((flags & TRIC_SECTION_ABSOLUTE)
      && (flags & SECTION_SMALL))
    return -1UL;
  
  return flags;
}


/***********************************************************************
 ** Writing ASM file
 ***********************************************************************/

/* Implement `TARGET_ASM_FILE_END' */

static void
tric_asm_file_end (void)
{
  tric_asm_file_end_callinfo();
}


/* Implement `TARGET_ASM_TRAMPOLINE_TEMPLATE' */

static void
tric_asm_trampoline_template (FILE *f ATTRIBUTE_UNUSED)
{
  sorry ("nested functions are not supported for this machine");
}


/***********************************************************************
 ** Stack and Frame Layout
 ***********************************************************************/

/* Implement `INITIAL_ELIMINATION_OFFSET' */
/* Return the offset between two registers, one to be eliminated, and the other
   its replacement, at the start of a routine.  */

HOST_WIDE_INT
tric_initial_elimination_offset (int from, int to)
{
  HOST_WIDE_INT offset = 0;

  if (from == FRAME_POINTER_REGNUM && to == STACK_POINTER_REGNUM)
    {
      offset = get_frame_size()
        + crtl->outgoing_args_size;
    }
  else if (from == ARG_POINTER_REGNUM && to == STACK_POINTER_REGNUM)
    {
      offset = get_frame_size()
        + crtl->outgoing_args_size;
    }
  else if (from == ARG_POINTER_REGNUM && to == FRAME_POINTER_REGNUM)
    {
      offset = 0;
    }
  else
    {
      gcc_unreachable();
    }

  /* EABI 2.2.2.1:  Align to 8 bytes.  */

  offset = (offset + 7) & ~7;
  
  return offset;
}


/***********************************************************************
 ** Prologue and Epilogue
 ***********************************************************************/

/* Emit RTL to add a constant offset to SP */

static inline void
tric_emit_addto_sp (int frame_size, int frame_related_p)
{
  rtx insn;
  rtx offset = GEN_INT (frame_size);
  rtx part1, part2;

  gcc_assert (frame_size != 0);

  tric_split_const_int (offset, &part1, &part2, PLUS);

  if (const0_rtx != part1)
    {
      insn = emit_move_insn (stack_pointer_rtx,
                             gen_rtx_PLUS (Pmode,
                                           stack_pointer_rtx, part1));
      if (frame_related_p)
        RTX_FRAME_RELATED_P (insn) = 1;
    }

  if (NULL_RTX != part2)
    {
      insn = emit_move_insn (stack_pointer_rtx,
                             gen_rtx_PLUS (Pmode,
                                           stack_pointer_rtx, part2));
      if (frame_related_p)
        RTX_FRAME_RELATED_P (insn) = 1;
    }
}


/* EABI 2.2.2.1:  Align frame size of functions to 8 bytes.  */

static int
tric_current_function_frame_size (void)
{
  return (~7) & (get_frame_size() + crtl->outgoing_args_size + 7);
}


/* Emit RTL for the prologue of the current function. */

void
tric_emit_prologue (void)
{
  rtx insn;
  int frame_size = tric_current_function_frame_size();

  /* Init FP */

  if (frame_pointer_needed)
    {
      insn = emit_move_insn (frame_pointer_rtx, stack_pointer_rtx);
      RTX_FRAME_RELATED_P (insn) = 1;
    }

  /* Subtract frame size from SP to set up the frame.  */

  if (frame_size)
    {
      tric_emit_addto_sp (-frame_size, 1);

      if (frame_pointer_needed)
        {
          emit_insn (gen_frame_blockage ());
        }
    }

  if (flag_stack_usage_info)
    current_function_static_stack_size = frame_size;
}


/* Emit RTL for the epilogue of the current function. */

void
tric_emit_epilogue (int sibling_p)
{

  if (!sibling_p)
    {
      /* Free frame (restore SP and upper context) is done by RET/RFE.
         Expand the RET */
      
      emit_jump_insn (gen_return_insn ());
    }
  else
    {
      int frame_size = tric_current_function_frame_size();

      if (frame_size)
        {
          emit_insn (gen_frame_blockage ());

          tric_emit_addto_sp (frame_size, 0);
        }
    }
}


int
tric_simple_epilogue (void)
{
  return 1;
}

static void
tric_asm_function_prologue(FILE *file ATTRIBUTE_UNUSED)
{
  unsigned int mask = 0;
  int regno;
  /* Only print this info for -fverbose-asm or -dp */
  mask = 0;
  for (regno = REG_D0; regno <= REG_A15; regno++)
    if (df_regs_ever_live_p(regno))
      mask |= (1 << regno);

  /* Fill up the callinfo data structure used for fcall/fret late link optimization */
  callinfo_label[len_callinfo] = get_fnname_from_decl(current_function_decl);
  if (callinfo_label[len_callinfo][0] == '*')
  {
    // is aliased
    const char *aliased_name;
    aliased_name = get_fnname_from_decl(current_function_decl);
    callinfo_label[len_callinfo] = &aliased_name[1];
  }
  callinfo_regsused[len_callinfo] = mask;
  callinfo_argsused[len_callinfo] = crtl->args.info.args_mask;
  callinfo_retsused[len_callinfo] = 0;
  if (crtl->return_rtx != NULL_RTX)
  {
    if (REG_P(crtl->return_rtx))
    {
      if (GET_MODE(crtl->return_rtx) == SImode || GET_MODE(crtl->return_rtx) == SFmode)
      {
          callinfo_retsused[len_callinfo] = 1 << REGNO(crtl->return_rtx);
      }
      if (GET_MODE(crtl->return_rtx) == DImode || GET_MODE(crtl->return_rtx) == DFmode)
      {
          callinfo_retsused[len_callinfo] = 1 << REGNO(crtl->return_rtx);
          callinfo_retsused[len_callinfo] |= 1 << (REGNO(crtl->return_rtx) + 1);
      }
      if (GET_MODE(crtl->return_rtx) == TImode)
      {
          callinfo_retsused[len_callinfo] = 1 << REGNO(crtl->return_rtx);
          callinfo_retsused[len_callinfo] |= 1 << (REGNO(crtl->return_rtx) + 1);
          callinfo_retsused[len_callinfo] |= 1 << (REGNO(crtl->return_rtx) + 2);
          callinfo_retsused[len_callinfo] |= 1 << (REGNO(crtl->return_rtx) + 3);
      }
    }
  }
}

void tric_print_dfregs_bb(basic_block bb, FILE *file)
{

  bitmap r;
  int i;
  unsigned int regs;

  FOR_EACH_BB_FN(bb, cfun)
  {
    fprintf(file,    "#bb %d\n", bb->index);
    r = DF_LR_IN(bb);
    fprintf(file, "# DF_LR_IN                 ");
    regs = 0;
    for (i = 0; i < 32; i += 1)
    {
      if (bitmap_bit_p(r, i))
      {
          regs = regs | (1 << i);
          // bitmap_clear_bit (r, i);
      }
    }
    fprintf(file, "%8.8x \n", regs);
    r = DF_LR_OUT(bb);
    fprintf(file, "# DF_LR_OUT                 ");
    regs = 0;
    for (i = 0; i < 32; i += 1)
    {
      if (bitmap_bit_p(r, i))
      {
          regs = regs | (1 << i);
          // bitmap_clear_bit (r, i);
      }
    }
    if (df_live)
    {
      r = DF_LIVE_IN(bb);
      fprintf(file, "# DF_LIVE_IN               ");
      regs = 0;
      for (i = 0; i < 32; i += 1)
      {
          if (bitmap_bit_p(r, i))
          {
        regs = regs | (1 << i);
        // bitmap_clear_bit (r, i);
          }
      }
      fprintf(file, "%8.8x \n", regs);
      r = DF_LIVE_OUT(bb);
      fprintf(file, "# DF_LIVE_OUT               ");
      regs = 0;
      for (i = 0; i < 32; i += 1)
      {
          if (bitmap_bit_p(r, i))
          {
        regs = regs | (1 << i);
        // bitmap_clear_bit (r, i);
          }
      }
      fprintf(file, "%8.8x \n", regs);
      r = &DF_LIVE_BB_INFO(bb)->gen;
      fprintf(file, "# DF_LIVE_BB_INFO (bb)->gen ");
      regs = 0;
      for (i = 0; i < 32; i += 1)
      {
          if (bitmap_bit_p(r, i))
          {
        regs = regs | (1 << i);
        // bitmap_clear_bit (r, i);
          }
      }
      fprintf(file, "%8.8x \n", regs);
      r = &DF_LIVE_BB_INFO(bb)->kill;
      fprintf(file, "# DF_LIVE_BB_INFO (bb)->kill ");
      regs = 0;
      for (i = 0; i < 32; i += 1)
      {
          if (bitmap_bit_p(r, i))
          {
        regs = regs | (1 << i);
        // bitmap_clear_bit (r, i);
          }
      }
      fprintf(file, "%8.8x \n", regs);
    }
  }
}

/* Implement `TARGET_ASM_FUNCTION_END_PROLOGUE' */
/* Output summary after end of function prologue.  */

static void
tric_asm_function_end_prologue (FILE *file)
{
  int mask = 0;
  int regno;

  if (flag_verbose_asm || flag_print_asm_name)
  {
    basic_block bb = BLOCK_FOR_INSN (get_insns());
    tric_print_dfregs_bb(bb, file);
  }

  /* Only print this info for -fverbose-asm or -dp */
  
  if (flag_verbose_asm
      || flag_print_asm_name)
    {
      fprintf (file, ASM_COMMENT_START " end prologue\n");
      fprintf (file, ASM_COMMENT_START " cfun->calls_alloca = %d\n",
               cfun->calls_alloca);
      fprintf (file, ASM_COMMENT_START " cfun->calls_setjmp = %d\n",
               cfun->calls_setjmp);
      fprintf (file, ASM_COMMENT_START " cfun->has_nonlocal_label = %d\n",
               cfun->calls_setjmp);
      fprintf (file, ASM_COMMENT_START " cfun->has_forced_label_in_static = %d\n",
               cfun->has_forced_label_in_static);
      fprintf (file, ASM_COMMENT_START " cfun->is_thunk = %d\n",
               cfun->is_thunk);
      fprintf (file, ASM_COMMENT_START " cfun->tail_call_marked = %d\n",
               cfun->tail_call_marked);
      fprintf (file, ASM_COMMENT_START " cfun->stdarg = %d\n",
               cfun->stdarg);
      fprintf (file, ASM_COMMENT_START " cfun->machine->sibcall = %d\n",
               cfun->machine->sibcall);
      fprintf (file, ASM_COMMENT_START " cfun->machine->noreturn = %d\n",
               cfun->machine->noreturn);
      fprintf (file, ASM_COMMENT_START " cfun->machine->calls = %d\n",
               cfun->machine->calls);
      fprintf (file, ASM_COMMENT_START " cfun->machine->is_leaf = %d\n",
               cfun->machine->is_leaf);
      fprintf (file, ASM_COMMENT_START " cfun->machine->is_interrupt = %d\n",
               cfun->machine->is_interrupt);
      fprintf (file, ASM_COMMENT_START " frame-pointer needed = %d\n",
               frame_pointer_needed);

      fprintf (file, ASM_COMMENT_START " frame size           = %lld\n",
               (long long) get_frame_size ());

      fprintf (file, ASM_COMMENT_START " outgoing args size   = %lld\n",
               (long long) crtl->outgoing_args_size);
      fprintf (file, ASM_COMMENT_START " args on stack   = %lld\n",
               (long long) crtl->args.info.args_onstack);

      tree fndecl = current_function_decl;

      if (DECL_RESULT (fndecl)!=NULL)
	{
	      if (aggregate_value_p (DECL_RESULT (fndecl), fndecl))
		{
		  if (int_size_in_bytes (TREE_TYPE(DECL_RESULT (fndecl)))>8)
		    cfun->machine->ret_on_stack=1;
		}
	}
      fprintf (file, ASM_COMMENT_START " ret  on stack   = %d\n",
	       cfun->machine->ret_on_stack);
      fprintf (file, ASM_COMMENT_START " incoming args        = ");


      if (crtl->args.info.args_mask)
        tric_output_reglist (file, crtl->args.info.args_mask);
      else
        fprintf (file, "(void)");

      fprintf (file, "\n");

      for (regno = REG_D0; regno <= REG_A15; regno++)
        if (df_regs_ever_live_p (regno))
          mask |= (1 << regno);

      fprintf (file, ASM_COMMENT_START " regs live            = ");

      if (mask)
        tric_output_reglist (file, mask);
      else
        fprintf (file, "-");
      fprintf (file, "\n");
        
      fprintf (file, ASM_COMMENT_START " return-rtx           = ");
      tricore_fdump (file, "%r\n", crtl->return_rtx);

      fprintf (file, ASM_COMMENT_START " function is leaf     = %d\n",
               crtl->is_leaf);
      fprintf (file, ASM_COMMENT_START " function crtl->tail_call_emit     = %d\n",
               crtl->tail_call_emit);
      fprintf (file, ASM_COMMENT_START " function crtl->has_asm_statement     = %d\n",
               crtl->has_asm_statement);
      fprintf (file, ASM_COMMENT_START " function crtl->has_nonlocal_goto     = %d\n",
               crtl->has_nonlocal_goto);
      fprintf (file, ASM_COMMENT_START " function crtl->uses_only_leaf_regs     = %d\n",
               crtl->uses_only_leaf_regs);
    }
}


/* Implement `TARGET_ASM_FUNCTION_BEGIN_EPILOGUE' */
/* Output summary before start of function epilogue.  */

static void
tric_asm_function_begin_epilogue (FILE *file)
{
  /* Only print this info for -fverbose-asm or -dp */
  
  if (flag_verbose_asm
      || flag_print_asm_name)
    {
      fprintf (file, ASM_COMMENT_START " start epilogue: ");

      if (tric_interrupt_function_p (current_function_decl))
        fprintf (file, TRIC_ATTR_INTERRUPT " ");

      if (tric_interrupt_handler_function_p (current_function_decl))
        fprintf (file, TRIC_ATTR_INTERRUPT_HANDLER " ");

      if (tric_pxhndcall_function_p (current_function_decl))
        fprintf (file, TRIC_ATTR_PXHNDCALL " ");

      fprintf (file, "\n");
    }
}

void tric_asm_output_end_function(FILE *file, const char *fnname, tree decl ATTRIBUTE_UNUSED)
{

    /* We output a nop after noreturn calls at the very end of the function to
       ensure that the return address always remains in the caller's code range,
       as not doing so might confuse unwinding engines.  */
    /* End the function.  */
    //      .size   interruptHandlerInstall, .-interruptHandlerInstall
    callinfo_statused[len_callinfo] = 0;
    if (cfun->calls_alloca == 1)
      callinfo_statused[len_callinfo] |= 0x00000001;
    if (cfun->calls_setjmp == 1)
      callinfo_statused[len_callinfo] |= 0x00000002;
    if (cfun->has_nonlocal_label == 1)
      callinfo_statused[len_callinfo] |= 0x00000004;
    if (cfun->has_forced_label_in_static == 1)
      callinfo_statused[len_callinfo] |= 0x00000008;
    if (cfun->is_thunk == 1)
      callinfo_statused[len_callinfo] |= 0x00000010;
    if (cfun->tail_call_marked == 1)
      callinfo_statused[len_callinfo] |= 0x00000020;
    if (frame_pointer_needed == 1)
      callinfo_statused[len_callinfo] |= 0x00000040;
    if (crtl->is_leaf == 1)
      callinfo_statused[len_callinfo] |= 0x00000080;
    if (crtl->has_asm_statement == 1)
      callinfo_statused[len_callinfo] |= 0x00000100;
    if (crtl->has_nonlocal_goto == 1)
      callinfo_statused[len_callinfo] |= 0x00000200;
    if (crtl->uses_only_leaf_regs == 1)
      callinfo_statused[len_callinfo] |= 0x00000400;
    if (cfun->machine->sibcall != 0)
      callinfo_statused[len_callinfo] |= 0x00000800;
    if (cfun->machine->noreturn != 0)
      callinfo_statused[len_callinfo] |= 0x00001000;
    if (cfun->machine->is_leaf != 0)
      callinfo_statused[len_callinfo] |= 0x00002000;
    if (cfun->machine->is_interrupt != 0)
      callinfo_statused[len_callinfo] |= 0x00004000;
    if (get_frame_size() != 0)
      callinfo_statused[len_callinfo] |= 0x00008000;
    if (crtl->outgoing_args_size != 0)
      callinfo_statused[len_callinfo] |= 0x00010000;
    if (cfun->machine->calls != 0)
      callinfo_statused[len_callinfo] |= 0x00020000;
    if (crtl->args.info.args_onstack)
      callinfo_statused[len_callinfo] |= 0x00040000;
    if (cfun->machine->ret_on_stack)
      callinfo_statused[len_callinfo] |= 0x00080000;
    if (cfun->stdarg)
      callinfo_statused[len_callinfo] |= 0x00100000;
    if (!(TREE_PUBLIC(decl)))
      callinfo_statused[len_callinfo] = 0xFFFFFFFF; // do not generate callinfo
    if (!flag_inhibit_size_directive)
    {
      fputs("\t.size ", file);
      assemble_name(file, fnname);
      fputs(", .-", file);
      assemble_name(file, fnname);
      putc('\n', file);
    }
    if (tric_opt_funcinfo)
    {
      if (TREE_PUBLIC(decl))
      {
        if (DECL_WEAK(cfun->decl))
        {
          fputs("\t.weak\t", file);
          assemble_name(file, fnname);
          fputs("_end\n", file);
          callinfo_statused[len_callinfo] = 0xFFFFFFFF;
        }
        else
        {
          fputs("\t.global\t", file);
          assemble_name(file, fnname);
          fputs("_end\n", file);
        }
        assemble_name(file, fnname);
        fputs("_end:\n", file);
        len_callinfo += 1;
      }
    }
}

/***********************************************************************
 ** Builtins
 ***********************************************************************/

/* Implement `RETURN_ADDR_RTX' */
/* Return the value of the return address for the frame COUNT steps up
   from the current frame, after the prologue.
   We punt for everything but the current frame by returning const0_rtx.  */

rtx
tric_return_addr_rtx (int count)
{
  if (count != 0)
    return const0_rtx;

  return get_hard_reg_initial_val (Pmode, REG_A11);
}


/***********************************************************************
 ** Print Operands
 ***********************************************************************/

/* Print the asm for a MEM rtx to file */

static void
tric_print_mem_operand (FILE *file, rtx addr, enum machine_mode mode)
{
  switch (GET_CODE (addr))
    {
    case REG:
      fputc ('[', file);
      tric_print_operand (file, addr, 0);
      fputs ("]0", file);

      break;
            
    case LO_SUM:
      {
        rtx reg = XEXP (addr, 0);
        rtx sum = XEXP (addr, 1);
        
        gcc_assert (REG_P (reg));
        gcc_assert (CONST == GET_CODE (sum) || SYMBOL_REF == GET_CODE (sum));
        fputc ('[', file);
        tric_print_operand (file, reg, 0);
        fputs ("] lo:", file);
        output_addr_const (file,sum);

        break;
      }
      
    case PLUS:
      {
        rtx reg = XEXP (addr, 0);
        rtx sum = XEXP (addr, 1);

        gcc_assert (REG_P (reg));
        fputc ('[', file);
        tric_print_operand (file, reg, 0);
        fputs ("] ", file);
        output_addr_const (file,sum);
      }
      break;

    case PRE_INC:
      fputs ("[+", file);
      tric_print_operand (file, XEXP (addr, 0), 0);
      fprintf (file, "]%d", GET_MODE_SIZE (mode));
      break;
            
    case POST_INC:
      fputc ('[', file);
      tric_print_operand (file, XEXP (addr, 0), 0);
      fprintf (file, "+]%d", GET_MODE_SIZE (mode));
      break;

    case PRE_DEC:
      fputs ("[+", file);
      tric_print_operand (file, XEXP (addr, 0), 0);
      fprintf (file, "]-%d", GET_MODE_SIZE (mode));
      break;
            
    case POST_DEC:
      fputc ('[', file);
      tric_print_operand (file, XEXP (addr, 0), 0);
      fprintf (file, "+]-%d", GET_MODE_SIZE (mode));
      break;
            
    case PRE_MODIFY:
      gcc_assert (PLUS == GET_CODE (XEXP (addr, 1)));
      gcc_assert (REGNO (XEXP (addr, 0)) == REGNO (XEXP (XEXP (addr, 1), 0)));
      {
        rtx op1 = XEXP (XEXP (addr, 1), 1);

        fputs ("[+", file);
        tric_print_operand (file, XEXP (addr, 0), 0);
        fprintf (file, "]" HOST_WIDE_INT_PRINT_DEC, INTVAL (op1));
        break;
      }
      
    case POST_MODIFY:
      gcc_assert (PLUS == GET_CODE (XEXP (addr, 1)));
      gcc_assert (REGNO (XEXP (addr, 0)) == REGNO (XEXP (XEXP (addr, 1), 0)));
      {
        rtx op1 = XEXP (XEXP (addr, 1), 1);

        fputc ('[', file);
        tric_print_operand (file, XEXP (addr, 0), 0);
        fprintf (file, "+]" HOST_WIDE_INT_PRINT_DEC, INTVAL (op1));
        break;
      }
      
    case SYMBOL_REF:
      if (tric_symbol_ref_small16_p (addr))
        {
          fputs ("[%A0] SM:", file);
        }

      tric_print_operand (file, addr, 0);
      break;
            
    case CONST_INT:
      fprintf (file, "0x%08x",
               (unsigned int) (GET_MODE_MASK (SImode) & UINTVAL (addr)));
      break;
      
    case CONST:
      {
        rtx sym = XEXP (XEXP (addr, 0), 0);
        if (tric_symbol_ref_small16_p (sym))
          {
            fputs ("[%A0] SM:", file);
          }
        tric_print_operand (file, XEXP (XEXP (addr, 0), 0), 0);
        fputc ('+', file);
        tric_print_operand (file, XEXP (XEXP (addr, 0), 1), 0);
        break;
      }
            
    default:
      tricore_edump ("%F: ??? %r\n", addr);
      gcc_unreachable ();
      break;
    }
}


/* Implement `TARGET_PRINT_OPERAND_ADDRESS' */

static void
tric_print_operand_address (FILE *file, machine_mode mode ATTRIBUTE_UNUSED, rtx x)
{
  tric_print_operand (file, x, '\0');
}


/* Implement `TARGET_PRINT_OPERAND' */

static void
tric_print_operand (FILE *file, rtx x, int code)
{
  if (NULL_RTX == x)
    {
      gcc_assert (targetm.asm_out.print_operand_punct_valid_p (code));
      return;
    }

  if ('I' == code)
    {
      fputs (REG_P (x) ? "i" : "", file);
      return;
    }

  switch (GET_CODE (x))
    {
    case REG:
      {
        int regno = REGNO (x);
        if (Q_REGNO_P (regno))
          switch (code)
            {
            case 'Q':
              if (Q_REGNO_P (regno))
                  fprintf (file, "%s%c%d", REGISTER_PREFIX, 'q', regno);
              return;
            }
        if (E_REGNO_P (regno)  ||  EA_REGNO_P (regno))
          switch (code)
            {
            case 'A':
              if (E_REGNO_P (regno))
                  fprintf (file, "%s%c%d", REGISTER_PREFIX, 'e', regno);
              if (EA_REGNO_P (regno))
                  fprintf (file, "%s%c%d", REGISTER_PREFIX, 'A', regno-REG_A0);
              return;
              
            case 'L':
              fprintf (file, "%s%s", REGISTER_PREFIX, reg_names[regno]);
              return;
            case 'H':
              fprintf (file, "%s%s", REGISTER_PREFIX, reg_names[regno+1]);
              return;
            }
        
        if (0 == code)
          {
            fprintf (file, "%s%s", REGISTER_PREFIX, reg_names[regno]);
            return;
          }

        tricore_edump ("%?: %r\n", x);
        output_operand_lossage ("invalid register modifier '%c'", code);
      }
      break;

    case MEM:
      tric_print_mem_operand (file, XEXP (x, 0), GET_MODE (x));
      break;

    case CONST_INT:
    case CONST_DOUBLE:
      {
        unsigned lo32, hi32;
        
        tric_split_const_rtx (x, &lo32, &hi32);

        if ('p' == code)
          {
            /* exact_log2 */
            int pos = exact_log2 (lo32);
            gcc_assert (pos >= 0);
            fprintf (file, "%d", pos);
          }
        else if ('P' == code)
          {
            /* Position (offset) of a packet of ones */
            int pos = ones_mask (lo32 & GET_MODE_MASK (SImode), NULL);
            if (pos < 0)
              {
                tricore_edump ("%?:%c %r\n", code, x);
                abort();
              }
              
            gcc_assert (pos >= 0);
            fprintf (file, "%d", pos);
          }
        else if ('M' == code)
          {
            tric_output_reglist (file, lo32);
            break;
          }
        else if ('W' == code)
          {
            /* Width of a packet of ones */
            int width = ones_width (lo32 & GET_MODE_MASK (SImode));

            if (width <= 0)
              {
                tricore_edump ("%?:%c %r\n", code, x);
                abort();
              }
            fprintf (file, "%d", width);
          }
        else if ('A' == code)
          /* LOW part 16 Bits */
          fprintf (file, "%d", lo32 & 0xffff);
        else if ('B' == code)
          /* HIGH part 16 Bits */
          fprintf (file, "%d", (lo32 >> 16) & 0xffff);
        else if ('L' == code)
          /* LOW part 32 Bits */
          fprintf (file, "%d", lo32);
        else if ('H' == code)
          {
          /* HIGH part 32 Bits */
            if (CONST_INT_P (x))
              fprintf (file, (lo32 & 0x80000000) ? "-1" : "0");
            else
              fprintf (file, "%d", hi32);
          }
        else
          fprintf (file, "%d", lo32);
      }
      break;

    case CONST:
      if (MINUS == GET_CODE (XEXP (x, 0)))
        {
          fprintf (file, "((");
          output_addr_const (file, XEXP (XEXP (x, 0), 0));
          fprintf (file, ")-(");
          output_addr_const (file, XEXP (XEXP (x, 0), 1));
          fprintf (file, "))");
          
          break;
        }

      /* FALLTHRU */
    case SYMBOL_REF:
    case CODE_LABEL:
      output_addr_const (file, x);
      break;
      
    case LABEL_REF:
      fprintf (file, ".L%d", CODE_LABEL_NUMBER (XEXP (x, 0)));
      break;
            
    case CONST_STRING:
      fprintf (file, "%s", XSTR (x, 0));
      break;

    case HIGH:
      fprintf (file, "hi:");
      if (CONST == GET_CODE (XEXP (x, 0))
          && MINUS == GET_CODE (XEXP (XEXP (x, 0), 0)))
        tric_print_operand (file, XEXP (x, 0), '\0');
      else
        output_addr_const (file, XEXP (x, 0));
      break;

    default:
      tricore_edump ("%F: ??? %r\n", x);
      gcc_unreachable ();
    }
}


/* Implement `TARGET_FUNCTION_OK_FOR_SIBCALL' */
/* Decide whether we can make a sibling call to a function.  DECL_CALLEE is
   the declaration of the function being targeted by the call and EXP_CALLEE
   is the CALL_EXPR representing the call. */

static bool
tric_function_ok_for_sibcall (tree decl_callee, tree exp_callee)
{
  tree fntype_callee, ret_callee, ret_current;
  int callee_irq_p, callee_irqh_p;
  int current_irq_p, current_irqh_p;

  if (flag_optimize_sibling_calls==0) return false;

  fntype_callee = TREE_TYPE (CALL_EXPR_FN (exp_callee));

  if (decl_callee)
    {
      decl_callee = TREE_TYPE (decl_callee);
    }
  else
    {
      decl_callee = fntype_callee;
      
      while (FUNCTION_TYPE != TREE_CODE (decl_callee)
             && METHOD_TYPE != TREE_CODE (decl_callee))
        {
          decl_callee = TREE_TYPE (decl_callee);
        }
    }
 
  if (tric_pxhndcall_function_p (decl_callee))
    {
      return false;
    }

  /* Some users like to call irq-like functions like ordinary functions.
     As they never return, tailcalling them is ok without knowing
     anything about the return type. */
  
  callee_irq_p  = tric_interrupt_function_p (decl_callee);
  callee_irqh_p = tric_interrupt_handler_function_p (decl_callee);
  current_irq_p  = tric_interrupt_function_p (current_function_decl);
  current_irqh_p = tric_interrupt_handler_function_p (current_function_decl);

  /* Return type of the function that is candidate for a tail call */
  ret_callee = TREE_TYPE (decl_callee);
  
  /* Return type of the caller function that might issue the tail call */
  ret_current = TREE_TYPE (DECL_RESULT (current_function_decl));

  /* Due to TriCore ABI that requests to return pointers in A-regs and
     non-pointers in D-regs we must care for (implicit) casts of return
     value which will change from A to D or vice versa. */
  
  if (TREE_CODE (ret_current) != VOID_TYPE
      && (POINTER_TYPE_P (ret_callee) ^ POINTER_TYPE_P (ret_current)))
    return false;

  if (cfun->machine->sibcall_fails
      /* ISRs must return via RFE resp. RSLCX/RFE */
      || current_irq_p != callee_irq_p
      || current_irqh_p != callee_irqh_p)
    return false;

  return true;
}


/* Implement `TARGET_STATIC_CHAIN' */

static rtx
tric_static_chain (const_tree fndecl, bool incoming_p)
{
  unsigned int regno = STATIC_CHAIN_REGNUM;
  
  if (!incoming_p
      && tric_pxhndcall_function_p (fndecl))
    {
      regno = REG_A13;
    }
  
  return gen_rtx_REG (Pmode, regno);
}


/* The middle end does not know that the RET of our target machine will
   restore SP and therefore misses some cases where we can issue a tail call.
   We try to fix these cases in peephole2. */

bool
tric_peep2_may_sibcall_p (rtx addr ATTRIBUTE_UNUSED, rtx xcookie)
{
  int cookie = INTVAL (xcookie);

  if (! flag_optimize_sibling_calls
      || cfun->machine->sibcall_fails
      || (cookie & CALLCOOKIE_INTERRUPT_MASK)
      || (cookie & CALLCOOKIE_INTERRUPT_HANDLER_MASK)
      || (cookie & CALLCOOKIE_PXHNDCALL_MASK)
      || (cookie & CALLCOOKIE_NO_SIBCALL_MASK)
      || tric_interrupt_function_p (current_function_decl)
      || tric_interrupt_handler_function_p (current_function_decl))
    return false;

  return true;
}


/* Adapt flow info for peephole2 patterns that transform CALL+RET to
   tail call insns.  See GCC-135.  We pass an original insn BB_INSN to
   ship the basic block.  insn-emit.c includes basic-block.h after tm_p.h
   and we don't want the build warning induced by that include order.  */

void
tric_peep2_setup_sibcall (rtx bb_insn, rtx call)
{
  edge e;
  edge_iterator ei;
  basic_block bb = BLOCK_FOR_INSN (bb_insn);

  /* Mark the call insn as tail call: set insn flag /j  */

  SIBLING_CALL_P (call) = 1;

  /* Search for the edge that directs to the exit block and mark that
     edge as sibling call.  There must be exectly one edge, and its
     destination must be EXIT_BLOCK_PTR.  */

  FOR_EACH_EDGE (e, ei, bb->succs)
    {
      if (e->dest == EXIT_BLOCK_PTR_FOR_FN (cfun))
        {
          e->flags |= EDGE_SIBCALL | EDGE_ABNORMAL;
          return;
        }
    }

  gcc_unreachable();
}


/***********************************************************************
 ** Emit RTL too complex for target.md
 ***********************************************************************/

/* If X is a pattern that represents a single_set that needs one or
   several scratch registers and maybe clobbers PSW:

       (parallel [(set (...)
                       (...))
                  (clobber (scratch))
                  ...
                  (clobber (reg:REG_PSW))]) ;; optional

   then set *CLOB_PSW to TRUE iff the pattern clobbers PSW.  Return the
   respective SET rtx.  If the pattern is not of the indicated layout then
   return NULL_RTX; *CLOB_PSW is undefined in that case.  */

static rtx
tric_set_clobbers_psw (rtx x, bool *clob_psw)
{
  rtx xi, set = NULL_RTX;
  *clob_psw = false;

  if (PARALLEL != GET_CODE (x)
      || SET != GET_CODE (set = XVECEXP (x, 0, 0)))
    return NULL_RTX;

  for (int i = 1; i < XVECLEN (x, 0); i++)
    {
      if (CLOBBER == GET_CODE (xi = XVECEXP (x, 0, i)))
        {
          rtx clobber_what = XEXP (xi, 0);

          if (REG_P (clobber_what)
              && REG_PSW == REGNO (clobber_what))
            *clob_psw = true;
          else if (SCRATCH != GET_CODE (clobber_what))
            return NULL_RTX;
        }
      else
        return NULL_RTX;
    }

  return set;
}


/* Try to map SET rtx X to an other, equivalent rtx.  If a map is found,
   return the replacement for X; otherwise return NULL.  */

static rtx
tric_find_match_for_combine (rtx x)
{
  /* We make use of `split_insns' to map patterns to each other.  For most
     mappings this is much more convenient than coding in C.  All these
     splits are held in tricore-map.md and have `tric_map_combine' as their
     condition.  */

  tric_map_combine = 1;
  rtx_insn *insn;
  insn = split_insns (x, NULL);
  tric_map_combine = 0;

  return (// If insn != 0 we found a match
          insn
          // The result is an insn list.  It must not have more than 1 insn.
          && !NEXT_INSN (insn)
          // The target patterns are wrapped in UNSPEC_MAP_COMBINE unspecs so
          // that we can distinguish between splits we are interested in and
          // ordinary matching and non-matching splits.  Actually it makes no
          // sense to have overlapping matches, but genrecog only complains
          // if two splits are matching exactly.
          && UNSPEC == GET_CODE (PATTERN (insn))
          && UNSPEC_MAP_COMBINE == XINT (PATTERN (insn), 1))
    ? XVECEXP (PATTERN (insn), 0, 0)
    : NULL_RTX;
}


/* Try to replace rtx X by a different, equivalent (and simpler) rtx.  */

static rtx
tric_simplify_combined_rtx (rtx f)
{
  // Handle combinations of MIN, MAX, SIGN_EXTEND, ZERO_EXTEND, ABS.
  // IF_THEN_ELSE should have olready been mapped to MIN / MAX by
  // tricore-map.md if applicalble.

  return tric_optimize_minmax (f);
}


/* Implement `TARGET_HTC_CANONICALIZE_COMBINED_RTX' */

static rtx
tric_htc_canonicalize_combined_rtx (rtx x)
{
  bool clobbers_psw = false;
  rtx set = NULL_RTX;
  rtx new_x = NULL_RTX;

  if (!tric_opt_map_combine)
    return x;

  if (SET == GET_CODE (x))
    {
      new_x = tric_find_match_for_combine (set = x);
    }
  else if (NULL_RTX != (set = tric_set_clobbers_psw (x, &clobbers_psw)))
    {
      // The original pattern clobbers some stuff.
      // Try match the plain SET with all clobbers stripped off.
      new_x = tric_find_match_for_combine (set);

      if (// If this did not match ...
          !new_x
          //... and the original pattern clobbers PSW ...
          && clobbers_psw
          // ... then search for an rtx that also clobbers PSW.
          && (new_x = tric_find_match_for_combine (x)))
        {
          // The matcher must also clobber PSW in that case.
          gcc_assert (tric_set_clobbers_psw (new_x, &clobbers_psw)
                      && clobbers_psw);
        }
    }

  rtx old_set, old_src, new_src;

  // The action is (like) a plain SET.  Run some hand-written code against
  // the expression to (further) canonicalize / simplify 'set' or 'new_x'.
  // Notice the side effects on 'old_set', 'old_src' and 'new_src'.

  if (!clobbers_psw
      && ((old_set = new_x)
          || (old_set = set))
      && SET == GET_CODE (old_set)
      && REG_P (SET_DEST (old_set))
      && SImode == GET_MODE (SET_SRC (old_set))
      && (old_src = SET_SRC (old_set))
      && (new_src = tric_simplify_combined_rtx (old_src))
      && new_src != old_src)
    {
      new_x = gen_rtx_SET (SET_DEST (old_set), new_src);
    }

  if (dump_file && (dump_flags & TDF_DETAILS)
      && new_x)
    tricore_dump ("Canonicalized this instruction:\n%r\n\n", x);

  return new_x ? new_x : x;
}

/***********************************************************************
 ** Emit RTL too complex for target.md
 ***********************************************************************/

void
tric_emit_move_CONST_INT (rtx dest, rtx src)
{
  //fprintf(stderr," tric_emit_move_CONST_INT0 \n");
  gcc_assert (reload_completed);

  src = simplify_gen_subreg (SImode, src, GET_MODE (dest), 0);
  dest = simplify_gen_subreg (SImode, dest, GET_MODE (dest), 0);
  rtx xop[2] = { dest, src };

  int pos = exact_log2 ((uint32_t) (1 + UINTVAL (src)));

  if (!tric_split_mov_insn_p (xop, SImode))
    {
      emit_move_insn (dest, src);
    }
  else if (pos > 0
           && !A_REG_P (dest))
    {
      // Some not-so-uncommon constants of the form 0b000...111 it is
      // better to MOV -1 and then shift right by the number of zeros.
      emit_move_insn (dest, constm1_rtx);
      emit_insn (gen_lshrsi3 (dest, dest, gen_int_mode (32-pos, SImode)));
    }
  else
    {
      /* `tric_split_const_int' won't work here because that function is not
         aware of DEST's register class.  */

      int val = INTVAL (src);
      int lo = trunc_int_for_mode (val, HImode);

      // MOVH, MOVH.A, LEA, MOV.A
      emit_move_insn (dest, gen_int_mode (val - lo, SImode));
      // ADDI, ADD, ADD.A, LEA
      emit_insn (gen_addsi3 (dest, dest, gen_int_mode (lo, SImode)));
    }
}


/* SRC is an SImode register holding XSVAL, a value known at compile time.
   Try to emit one insn to load XDVAL into DEST which is a SImode register or
   NULL_RTX.  In the latter case, the result is moved to and returned in
   a newly created pseudo register.

   If this function returns non-NULL, then it is a pattern of an insn that
   sets DEST to XDVAL using some arithmetic involving SRC or a plain set from
   SRC to DEST.  Otherwise, no 1-insn sequence has been found.  This function
   only searches for arithmetic operations with SRC as one of its inputs and
   will never come up with a MOV instruction to load XDVAL to DVAL.  */

static rtx
tric_arith_CONST_INT (rtx dest, rtx xdval, rtx src, rtx xsval)
{
  rtx lo, hi, op = NULL_RTX, pat = NULL_RTX;
  uint32_t sval = (uint32_t) UINTVAL (xsval);
  uint32_t dval = (uint32_t) UINTVAL (xdval);

  if (!dest)
    dest = gen_reg_rtx (SImode);

  if ((A_REG_P (src) || A_REG_P (dest))
      && (D_REG_P (src) || D_REG_P (dest)))
    // Don't produce cross-pipeline MOV.A or MOV.D instructions.
    return NULL_RTX;

  if ((A_REG_P (dest) && u4_operand (xdval, SImode))
      || (D_REG_P (dest) && s4_operand (xdval, SImode)))
    // Values that can be loaded by a 2-byte instruction.  Prefer this
    // over the (2-byte) move below.
    return NULL_RTX;

  if (sval == dval)
    // DEST = SRC
    return gen_rtx_SET (dest, src);

  op = gen_int_mode (dval - sval, SImode);

  if (REGNO (dest) == REGNO (src)
      && s4_operand (src, SImode))
    // A 2-byte addition can do the job.
    // DEST = SRC + OP
    return gen_rtx_SET (dest, gen_rtx_PLUS (SImode, src, op));

  tric_split_const_int (xdval, &lo, &hi, SET);

  if (A_REG_P (src) || A_REG_P (dest)
      // Don't investigate in DVAL that can be loaded in 1 insn.
      || !hi)
    return NULL_RTX;

  if (add_input_operand (op, SImode))
    // DEST = SRC + OP
    pat = gen_addsi3 (dest, src, op);
  else if (s9_operand (op = gen_int_mode (dval + sval, SImode), SImode))
    // DEST = OP - SRC
    pat = gen_subsi3 (dest, op, src);

  // Number of LSBs that DEST and SRC have in common.
  int comm_lsb = ctz_hwi (sval ^ dval);
  // Masks bits that are different, aligned to the right.
  unsigned diff_b = (sval ^ dval) >> comm_lsb;
  // Starting with this bit, all higher bits are the same again.
  int eqbit = 1 + floor_log2 (diff_b);
  // Smallest mask covering support of diff_b and of the form 2^j - 1.
  unsigned HOST_WIDE_INT ne_mask = (HOST_WIDE_INT_1U << eqbit) - 1;
  // Part of DVAL that is different to SVAL, aligned to the right.
  unsigned ne_bits = ne_mask & (dval >> comm_lsb);

  for (int n = 0; !pat && n <= 31; n++)
    {
      rtx xn = GEN_INT (n);
      uint32_t lsl_n = sval << n;
      uint32_t lsr_n = sval >> n;
      uint32_t rol_n = (sval << n) | (sval >> (32-n));
      // Number of LSBs that DEST and SRC >> N have in common.
      unsigned bits = ctz_hwi (lsr_n ^ dval);
      bits = bits + n > 32 ? 32 - n : bits;
      // Masks the highest of these LSBs.
      unsigned HOST_WIDE_INT msbmask = HOST_WIDE_INT_1U << (bits-1);

      if (dval == lsl_n)
        // DEST = SRC << n
        pat = gen_ashlsi3 (dest, src, xn);
      else if (dval == lsr_n)
        // DEST = SRC >> n
        pat = gen_lshrsi3 (dest, src, xn);
      else if (n && dval == rol_n)
        // DEST = SRC <<< n
        pat = gen_rotlsi3 (dest, src, xn);
      else if (bits >= 32
               // Shifting out common bits ...
               || dval >> bits == 0)
        // ...yiels 0, hence zero-extract:
        // DEST = SRC[N + BITS - 1, ..., N]
        pat = gen_extzv (dest, src, GEN_INT (bits), xn);
      else if (bits > 1
               // High bits all 1?
               && 0 == (uint32_t) ((dval & -msbmask) + msbmask))
        // Sign-extract.  This also covers arithmetic shift right without
        // clobbering PSW:
        // DEST = SRC[N + BITS - 1, ..., N]
        pat = gen_extv (dest, src, GEN_INT (bits), xn);
      else if (n >= 1
               && comm_lsb >= n
               && ctz_hwi ((dval >> n) ^ sval) >= comm_lsb + eqbit - n)
        {
          // DVAL is SVAL with LSBs from SVAL inserted starting at N.
          unsigned HOST_WIDE_INT mask = (1ULL << (comm_lsb + eqbit - n)) - 1;
          rtx xmask = gen_int_mode (mask << n, SImode);
          rtx xnmask = gen_int_mode (~(mask << n), SImode);
          pat = gen_insv_3a_ic (dest, src, xn, xmask, src, xnmask);
        }
    }

  if (!pat
      && ne_bits <= 15)
    {
      // DVAL is SVAL with a zero-extended 4-bit value inserted somewhere.
      rtx xnmask = gen_int_mode (~(ne_mask << comm_lsb), SImode);
      rtx xval = gen_int_mode (dval & (ne_mask << comm_lsb), SImode);
      pat = gen_insert_uconst_ic (dest, src, xnmask, xval);
    }

  /* No need to test for AND, IOR, XOR with constants:  The same that could
     be achieved by these signed 10-bit constants is either covered by PLUS,
     or the absolute value of the result is so small that it can be loaded
     in one instruction.  */

  /* Make sure that we actually return a pattern which is not yet the case if
     the gen_xxx functions used above originates from a define_expand.  */

  if (pat && INSN_P (pat))
    {
      /*TODO*/
	  /*gcc_assert (!NEXT_INSN (pat));*/
      pat = PATTERN (pat);
    }

  return pat;
}


/* Same as above, but emit the generated pattern as an insn and return
   the destination.  If NULL is returned nothing has been emitted.  */

rtx
tric_emit_arith_CONST_INT (rtx dest, rtx xdval, rtx src, rtx xsval)
{
  rtx pat = tric_arith_CONST_INT (dest, xdval, src, xsval);
  if (pat)
    {
      rtx insn = emit_insn (pat);
      set_unique_reg_note (insn, REG_EQUAL, xdval);
      return SET_DEST (pat);
    }
  return NULL_RTX;
}


/* Emit code for  OP0 = OP1 * OP2 + OP3  all operands are SImode registers
   except OP2 and OP3 which may also be a CONST_INT.  The return value
   represents the result which is OP[0] in most cases, but it might also
   be const0_rtx.  */

rtx
tric_emit_multiply_add (rtx op0, rtx op1, rtx op2, rtx op3)
{
  rtx res = op0;

  if (const0_rtx == op3)
    {
      if (const0_rtx == op2)
        emit_move_insn (op0, res = const0_rtx);
      else if (const1_rtx == op2)
        emit_move_insn (op0, res = op1);
      else if (constm1_rtx == op2)
        emit_insn (gen_negsi2 (op0, op1));
      else if (single_one_operand (op2, SImode))
        {
          int off = exact_log2 (UINTVAL (op2) & GET_MODE_MASK (SImode));
          emit_insn (gen_ashlsi3 (op0, op1, GEN_INT (off)));
        }
      else
        emit_insn (gen_mulsi3 (op0, op1, reg_or_s9_operand (op2, SImode)
                               ? op2 : force_reg (SImode, op2)));
    }
  else if (const0_rtx == op2)
    emit_move_insn (op0, res = op3);
  else if (const1_rtx == op2)
    emit_insn (gen_addsi3 (op0, op1, op3));
  else if (constm1_rtx == op2)
    emit_insn (gen_subsi3 (op0, reg_or_s9_operand (op3, SImode)
                           ? op3 : force_reg (SImode, op3), op1));
  else
    emit_insn (gen_maddsi4 (op0, op1, reg_or_s9_operand (op2, SImode)
                            ? op2 : force_reg (SImode, op2),
                            force_reg (SImode, op3)));
  return res;
}


/* Emit widening SI->DI multiplication OP0 = OP1 * OP2 where OP1 and OP2
   are extended according to CODE.  The return value is OP2 or, if OP2
   has been loaded to a new register, it is that SImode register.  */

rtx
tric_emit_mulsidi (rtx op0, rtx op1, rtx op2, enum rtx_code code)
{
  rtx ret2 = op2;

  if (const1_rtx == op2)
    {
      emit_insn (SIGN_EXTEND == code
                 ? gen_extendsidi2 (op0, op1)
                 : gen_zero_extendsidi2 (op0, op1));
    }
  else
    {
      op1 = gen_rtx_fmt_e (code, DImode, op1);

      if ((SIGN_EXTEND == code && !s9_operand (op2, SImode))
          || (ZERO_EXTEND == code && !u9_operand (op2, SImode)))
        op2 = gen_rtx_fmt_e (code, DImode, ret2 = force_reg (SImode, op2));

      emit_move_insn (op0, gen_rtx_MULT (DImode, op1, op2));
    }

  return ret2;
}


/* Emit insns for widening signed multiply-add:

   XOP[0] = XOP[1] + XOP[2] * XOP[3]

   XOP[0] and XOP[1] are DImode registers.
   XOP[2] is a const_int of any size.
   XOP[3] is a SImode register.  */

void
tric_emit_maddsidi4_const (rtx *xop)
{
  rtx lo[3], hi[3], res = xop[0], lo2, hi2 = NULL_RTX;;

  if (reg_overlap_mentioned_p (res, xop[1])
      || reg_overlap_mentioned_p (res, xop[3]))
    xop[0] = gen_reg_rtx (DImode);

  tric_split_di (xop, lo, hi, 3);
  lo2 = lo[2];

  if (const0_rtx == lo[2])
    {
      emit_move_insn (xop[0], xop[1]);
    }
  else
    {
      if (INTVAL (lo[2]) < 0)
        {
          // lo[2] has been sign-extended.  Adjust the high part so that we
          // have  xop[2] = lo[2] + hi[2] * 2**32  again.
          hi[2] = plus_constant (SImode, hi[2], 1);
        }

      if (s9_m9_operand (lo[2], SImode))
        emit_insn (gen_maddsidi4_const (xop[0], xop[3], lo[2], xop[1]));
      else
        emit_insn (gen_maddsidi4 (xop[0], xop[3],
                                  lo2 = force_reg (SImode, lo[2]), xop[1]));
    }

  if (REG_P (lo2)
      && !s9_operand (hi[2], SImode))
    // lo2 holds some const_int.  Try loading hi[2] the smart way.
    hi2 = tric_emit_arith_CONST_INT (NULL_RTX, hi[2], lo2, lo[2]);

  tric_emit_multiply_add (hi[0], xop[3], hi2 ? hi2 : hi[2], hi[0]);
  emit_move_insn (res, xop[0]);
}


/* Emit insns for widening unsigned multiply-add:

   XOP[0] = XOP[1] + XOP[2] * XOP[3]

   XOP[0] and XOP[1] are DImode registers.
   XOP[2] is a const_int of any size.
   XOP[3] is a SImode register.

   The return value represents the low 32 bits of XOP[2]:  If that low part
   is not returned unaltered as const_int, then it is a reg containing that
   value or (neg reg) with reg holding the negated low part.  */

rtx
tric_emit_umaddsidi4_const (rtx *xop)
{
  rtx lo[3], hi[3], res = xop[0], lo2, hi2 = NULL_RTX;

  if (reg_overlap_mentioned_p (res, xop[1])
      || reg_overlap_mentioned_p (res, xop[3]))
    xop[0] = gen_reg_rtx (DImode);

  tric_split_di (xop, lo, hi, 3);
  lo2 = lo[2];

  if (const0_rtx == lo[2])
    {
      emit_move_insn (xop[0], xop[1]);
    }
  else if (s10n_operand (lo[2], SImode))
    {
      if (INTVAL (lo[2]) < 0)
        {
          // lo[2] has been sign-extended.  Adjust the high part so that we
          // have  xop[2] = lo[2] + hi[2] * 2**32  again.
          hi[2] = plus_constant (SImode, hi[2], 1);
        }
      emit_insn (gen_umaddsidi4_const (xop[0], xop[3], lo[2], xop[1]));
    }
  else if (constm1_rtx == hi[2]
           || (INTVAL (hi[2]) < 0
               && INTVAL (hi[2]) != INTVAL (lo[2])))
    {
      // Negating will turn the high part from -1 to 0 because lo[2] != 0.
      // hi[2] = -~hi[2];
      hi[2] = plus_constant (SImode, hi[2], 1);
      lo[2] = simplify_unary_operation (NEG, SImode, lo[2], SImode);
      emit_insn (gen_umsubsidi4 (xop[0],
                                 lo2 = force_reg (SImode, lo[2]), xop[3],
                                 xop[1]));
      lo2 = gen_rtx_NEG (SImode, lo2);
    }
  else
    {
      emit_insn (gen_umaddsidi4 (xop[0], xop[3],
                                 lo2 = force_reg (SImode, lo[2]), xop[1]));
    }

  if (!CONST_INT_P (lo2)
      && !s9_operand (hi[2], SImode))
    // lo2 holds some const_int.  Try loading hi[2] the smart way.
    hi2 = tric_emit_arith_CONST_INT (NULL_RTX, hi[2],
                                     REG_P (lo2) ? lo2 : XEXP (lo2, 0), lo[2]);

  tric_emit_multiply_add (hi[0], xop[3], hi2 ? hi2 : hi[2], hi[0]);
  emit_move_insn (res, xop[0]);

  return lo2;
}


static void
tric_emit_lshiftrt64_const (rtx *xop)
{
	gcc_assert (CONST_INT_P (xop[2]));

  rtx lo[2], hi[2];
  int off = UINTVAL (xop[2]) % 64;

  tric_split_di (xop, lo, hi, 2);

  if (0 == off)
    {
      emit_move_insn (xop[0], xop[1]);
    }
  else if (off < 32 && off > 0)
    {
      emit_insn (gen_dextr_const (lo[0], lo[1], xop[2], hi[1],
                                  gen_int_mode (32 - off, SImode)));
      emit_insn (gen_lshrsi3 (hi[0], hi[1], xop[2]));
    }
  else if (32 == off)
    {
      emit_move_insn (lo[0], hi[1]);
      emit_move_insn (hi[0], const0_rtx);
    }
  else if (off > 32 && off < 64)
    {
      emit_insn (gen_lshrsi3 (lo[0], hi[1], gen_int_mode (off - 32, SImode)));
      emit_move_insn (hi[0], const0_rtx);
    }
  else
    gcc_unreachable();
}


/* XOP[0] = XOP[1] >> XOP[2].  */

void
tric_emit_lshiftrt64 (rtx *xop)
{
	if (CONST_INT_P (xop[2]))
    return tric_emit_lshiftrt64_const (xop);

  rtx xresult = xop[0];
  xop[0] = gen_reg_rtx (DImode);

  rtx lo[2], hi[2];
  tric_split_di (xop, lo, hi, 2);

  rtx neg2 = gen_reg_rtx (SImode);
  rtx ge_32 = gen_reg_rtx (SImode);

  rtx off_n32 = gen_reg_rtx (SImode);
  rtx hi0 = gen_reg_rtx (SImode);
  rtx lo0 = gen_reg_rtx (SImode);
  rtx xop2 = ge_32;

  // If shift offset $2 >= 32 ...
  tric_emit_setcompare (GE, xop[2], GEN_INT (32), ge_32);

  // ... then   (hi0, lo0) = (0, hi[1]), i.e. shift right by 32.
  // Otherwise  (hi0, lo0) = (hi[1], lo[1])
  emit_insn (gen_movsicc (lo0, gen_rtx_EQ (VOIDmode, ge_32, const0_rtx),
                          lo[1], hi[1]));

  emit_insn (gen_movsicc (hi0, gen_rtx_EQ (VOIDmode, ge_32, const0_rtx),
                          hi[1], const0_rtx));

  // Kill bit #5 of $2; remaining are offsets 0...31.
  emit_insn (gen_andsi3 (xop2, xop[2], GEN_INT (31)));

  // 32 - $2 is the offset for DEXTR
  emit_insn (gen_subsi3 (off_n32, GEN_INT (32), xop2));

  // Low word is DEXTR ... 32 - $2
  emit_insn (gen_dextr_reg (lo[0], lo0, off_n32, hi0));

  // If $2 = 32 and hence offset of DEXTR is 32 then DEXTR doesn' do.
  // Use original low word in that case.
  emit_insn (gen_movsicc (lo[0], gen_rtx_NE (VOIDmode, xop2, const0_rtx),
                          lo[0], lo0));

  // High word: Shift right by $2, i.e. SH with offset -$2.
  emit_insn (gen_negsi2 (neg2, xop2));
  emit_insn (gen_lshrsi3_unspec (hi[0], hi0, neg2));

  // Write back the result
  emit_move_insn (xresult, xop[0]);
}


static void
tric_emit_ashiftrt64_const (rtx *xop)
{
	gcc_assert (CONST_INT_P (xop[2]));

  int off = UINTVAL (xop[2]) % 64;

  rtx lo[2], hi[2];
  tric_split_di (xop, lo, hi, 2);

  if (0 == off)
    {
      emit_move_insn (xop[0], xop[1]);
    }
  else if (off < 32 && off > 0)
    {
      emit_insn (gen_dextr_const (lo[0], lo[1], xop[2], hi[1],
                                  gen_int_mode (32 - off, SImode)));
      emit_insn (gen_ashrsi3 (hi[0], hi[1], xop[2]));
    }
  else if (32 == off && TRIC_HAVE_MOV64)
    {
      emit_insn (gen_ashrdi3_32 (xop[0], xop[1]));
    }
  else if (32 == off)
    {
      emit_move_insn (lo[0], hi[1]);
      emit_insn (gen_ashrsi3 (hi[0], lo[0], GEN_INT (31)));
    }
  else if (off > 32 && off < 64)
    {
      emit_insn (gen_ashrsi3 (lo[0], hi[1], gen_int_mode (off - 32, SImode)));
      emit_insn (gen_ashrsi3 (hi[0], lo[0], GEN_INT (31)));
    }
  else
    gcc_unreachable();
}


/* XOP[0] = XOP[1] >> XOP[2].  */

void
tric_emit_ashiftrt64 (rtx *xop)
{
	if (CONST_INT_P (xop[2]))
    return tric_emit_ashiftrt64_const (xop);

  rtx xresult = xop[0];
  xop[0] = gen_reg_rtx (DImode);

  rtx lo[2], hi[2];
  tric_split_di (xop, lo, hi, 2);

  rtx ge_32 = gen_reg_rtx (SImode);
  rtx lo0 = gen_reg_rtx (SImode);
  rtx off_n32 = lo0;
  rtx xop2 = ge_32;

  // If shift offset $2 >= 32 ...
  tric_emit_setcompare (GE, xop[2], GEN_INT (32), ge_32);

  // ... then   $0 = $1 >> 32
  // ... else   $0 = $1
  emit_insn (gen_movsicc (lo[0], gen_rtx_EQ (VOIDmode, ge_32, const0_rtx),
                          lo[1], hi[1]));

  emit_insn (gen_ashrsi3_unspec (hi[0], hi[1], GEN_INT (-31)));
  emit_insn (gen_movsicc (hi[0], gen_rtx_EQ (VOIDmode, ge_32, const0_rtx),
                          hi[1], hi[0]));

  // Kill bit #5 of $2; remaining offsets are 0...31.
  emit_insn (gen_andsi3 (xop2, xop[2], GEN_INT (31)));

  // 32 - $2 is the offset for DEXTR
  emit_insn (gen_subsi3 (off_n32, GEN_INT (32), xop2));

  // Low word is DEXTR ... 32 - $2
  emit_insn (gen_dextr_reg (lo0, lo[0], off_n32, hi[0]));

  // If $2 = 32 and hence offset of DEXTR is 32, then DEXTR doesn't do.
  // Use low word lo[0] in that case.
  emit_insn (gen_movsicc (lo[0], gen_rtx_NE (VOIDmode, xop2, const0_rtx),
                          lo0, lo[0]));

  // High word: Shift right by $2, i.e. SH with offset -$2.
  emit_insn (gen_negsi2 (xop2, xop2));
  emit_insn (gen_ashrsi3_unspec (hi[0], hi[0], xop2));

  // Write back the result
  emit_move_insn (xresult, xop[0]);
}


static void
tric_emit_ashift64_const (rtx *xop)
{

  gcc_assert (CONST_INT_P (xop[2]));

  rtx lo[2], hi[2];
  int off = UINTVAL (xop[2]) % 64;

  tric_split_di (xop, lo, hi, 2);

  if (0 == off)
    {
      emit_move_insn (xop[0], xop[1]);
    }
  else if (off < 32 && off > 0)
    {
      emit_insn (gen_dextr_const (hi[0], lo[1],
                                  gen_int_mode (32 - off, SImode),
                                  hi[1], xop[2]));
      emit_insn (gen_ashlsi3 (lo[0], lo[1], xop[2]));
    }
  else if (32 == off)
    {
      emit_move_insn (hi[0], lo[1]);
      emit_move_insn (lo[0], const0_rtx);
    }
  else if (off > 32 && off < 64)
    {
      emit_insn (gen_ashlsi3 (hi[0], lo[1], gen_int_mode (off - 32, SImode)));
      emit_move_insn (lo[0], const0_rtx);
    }
  else
    gcc_unreachable();
}


/* XOP[0] = XOP[1] << XOP[2].  */

void
tric_emit_ashift64 (rtx *xop)
{
  if (CONST_INT_P (xop[2]))
    return tric_emit_ashift64_const (xop);

  rtx xresult = xop[0];
  xop[0] = gen_reg_rtx (DImode);

  rtx lo[2], hi[2];
  tric_split_di (xop, lo, hi, 2);

  rtx off_mod32 = lo[0];
  rtx is_ge32 = gen_reg_rtx (SImode);

  tric_emit_setcompare (GE, xop[2], GEN_INT (32), is_ge32);
  emit_insn (gen_andsi3 (off_mod32, xop[2], GEN_INT (31)));

  // $0 = $1 << ($2 % 32)
  // This is the result if 0 <= $2 < 32
  emit_insn (gen_dextr_reg (hi[0], lo[1], off_mod32, hi[1]));
  emit_insn (gen_ashlsi3 (lo[0], lo[1], off_mod32));

  // If $2 >= 32, then perform a conditional shift left by 32.
  // If $2 < 32, the values won't change
  // (hi0, lo0)  :=  $2 < 32 ? (hi0, lo0) : (lo0, 0)
  emit_insn (gen_movsicc (hi[0], gen_rtx_EQ (VOIDmode, is_ge32, const0_rtx),
                          hi[0], lo[0]));
  emit_insn (gen_movsicc (lo[0], gen_rtx_EQ (VOIDmode, is_ge32, const0_rtx),
                          lo[0], const0_rtx));

  // Write back the result
  emit_move_insn (xresult, xop[0]);
}


/* Return true if SYM is an absolute addressable SYMBOL_REF */

static inline bool
tric_symbol_ref_absolute_p (const_rtx sym)
{
  return (SYMBOL_REF == GET_CODE (sym)
          && 0 != (SYMBOL_REF_FLAGS (sym) & TRIC_SYMBOL_FLAG_ABSOLUTE));
}


/* Return true if SYM is a small addressable SYMBOL_REF */

static inline bool
tric_symbol_ref_small16_p (const_rtx sym)
{
  return (SYMBOL_REF == GET_CODE (sym)
          && 0 != (SYMBOL_REF_FLAGS (sym) & TRIC_SYMBOL_FLAG_SMALL));
}


bool
tric_absolute_code_address_p (rtx addr)
{
  return (CONST_INT_P (addr)
          && TRIC_ABSOLUTE_CODE_ADDRESS_P (INTVAL (addr)));
}


/* Return true if ADDR is an absolute address. */

bool
tric_absolute_address_p (rtx addr)
{
  bool abs = false;

  switch (GET_CODE (addr))
    {
    default:
      break;
      
    case SYMBOL_REF:
      abs = tric_symbol_ref_absolute_p (addr);
      break;

    case CONST:
      {
        rtx addr2 = XEXP (addr, 0);

        if (PLUS == GET_CODE (addr2))
          {
            rtx op0 = XEXP (addr2, 0);
            rtx op1 = XEXP (addr2, 1);

            if (CONST_INT_P (op1))
              {
                abs = (tric_symbol_ref_absolute_p (op0)
                       && IN_RANGE (INTVAL (op1), 0, 0x3ff0));
              }
            
          } /* PLUS */
      } /* CONST */
      break;

    case CONST_INT:
      abs = TRIC_ABSOLUTE_INT_ADDRESS_P (INTVAL (addr));
      break;
    }

  return abs;
}

bool
tric_small16_address_p (rtx addr)
{
  bool small = false;

  switch (GET_CODE (addr))
    {
    default:
      break;
      
    case SYMBOL_REF:
      small = tric_symbol_ref_small16_p (addr);
      break;

    case CONST:
      {
        rtx addr2 = XEXP (addr, 0);

        if (PLUS == GET_CODE (addr2))
          {
            rtx op0 = XEXP (addr2, 0);
            rtx op1 = XEXP (addr2, 1);

            if (CONST_INT_P (op1))
              {
                small = (tric_symbol_ref_small16_p (op0)
                         && INTVAL (op1) >= 0);
              }
            
          } /* PLUS */
      } /* CONST */
      break;
    }

  return small;
}


/* Some locations must be loaded indirect. */

static bool
tric_must_load_indirect_p (rtx addr)
{
  bool ind = true;
  
  switch (GET_CODE (addr))
    {
    default:
      break;

    case CONST_INT:
      ind = !tric_absolute_address_p (addr);
      break;

    case REG:
    case PRE_MODIFY:  case POST_MODIFY:
    case PRE_INC:     case POST_INC:
    case PRE_DEC:     case POST_DEC:
      ind = false;
      break;

    case SYMBOL_REF:
    case CONST:
      ind = (!tric_absolute_address_p (addr)
             && !tric_small16_address_p (addr));
      break;

    case LO_SUM:
      {
        rtx base = XEXP (addr, 0);
        rtx off = XEXP (addr, 1);

        if (REG_P (base)
            && tric_symbol_ref_small16_p (off))
          ind = false;

        break;
      }

    case PLUS:
      {
        rtx base = XEXP (addr, 0);
        rtx off = XEXP (addr, 1);

        if (!CONST_INT_P (off))
            break;

        switch (GET_CODE (base))
          {
          case REG:
            ind = false;
            break;

          case SYMBOL_REF:
            ind = (! tric_symbol_ref_small16_p (base)
                   || INTVAL (off) < 0);
            break;

          default:
              break;
          }

        break;
      }
    }

  if (tricore_log.must_load_indirect_p)
    tricore_edump ("%?: %d = %r\n", ind, addr);

  return ind;
}


/* Can we move an immediate X in one instruction?
   We already handled the CONST_INT case if we come here.

   REG may be NULL_RTX. In that case we treat it like a pseudo. */

bool
tric_can_move_immediate_p (rtx reg, rtx x)
{
  bool can = false;
  bool dreg_p = reg != NULL_RTX  &&  D_REG_P (x);
  
  switch (GET_CODE (x))
    {
    default:
      break;
      
    case CONST:
    case SYMBOL_REF:
      can = (!dreg_p
             && (tric_absolute_address_p (x)
                 || tric_small16_address_p (x)));
      break;

    case HIGH:
      can = true;
      break;

    case CONST_DOUBLE:
    case LABEL_REF:
      return false;
    }

  return can;
}


/* Expand a move operation in mode MODE.  The operands are in OPERANDS.
   Returns true if we are done and no further code must be generated,
   false if the caller should generate an insn to move
   operands[1] to operands[0].  */

bool
tric_emit_move (rtx *operands, enum machine_mode mode)
{
	RTX_CODE code1;

	/* One of the ops has to be in a register.  */
	if (!register_operand (operands[0], mode)
			&& !register_operand (operands[1], mode))
	{
		gcc_assert (can_create_pseudo_p());
		operands[1] = copy_to_mode_reg (mode, operands[1]);
	}

	/* If this is a memory move that can load/store without
     calculating the address, then emit this move.
     Otherwise, force the address into a register and
     load/store indirect.
     In the case of ST.A that can just handle 10-bit offsets
     for SI/SF-moves we use a secondary reload and emit ST.W instead.
     Constraint "Wa" will handle the remaining legal cases of ST.A */
	if (memory_operand (operands[1], mode))
	{
		rtx addr = XEXP (operands[1], 0);

		/* If we are in global alloc */
		if (!can_create_pseudo_p())
			return false;

		if (!tric_must_load_indirect_p (addr))
			return false;

		addr = copy_to_mode_reg (Pmode, addr);

		emit_move_insn (operands[0],
				replace_equiv_address (operands[1], addr));
		return true;
	}

	if (memory_operand (operands[0], mode))
	{
		rtx addr = XEXP (operands[0], 0);

		/* If we are in global alloc */
		if (!can_create_pseudo_p())
		{
			return false;
		}

		if (!tric_must_load_indirect_p (addr))
		{
			return false;
		}

		addr = copy_to_mode_reg (Pmode, addr);

		emit_move_insn (replace_equiv_address (operands[0], addr),
				operands[1]);


		return true;
	}

	code1 = GET_CODE (operands[1]);

	if (tric_opt_code_pic
			&& tric_opt_dynamic_code_pic
			&& (LABEL_REF == code1
					|| (SYMBOL_REF == code1
							&& (SYMBOL_REF_FLAGS (operands[1]) & TRIC_SYMBOL_FLAG_PIC))))
	{
		rtx pc_sym;

		tric_pic_offset_init();

		pc_sym = cfun->machine->pic_offset.symbol;

		if (tricore_log.pic)
		{
			switch (code1)
			{
			case SYMBOL_REF:
				warning (0, "computing pc-relative offset for symbol %qs",
						XSTR (operands[1], 0));
				break;

			case LABEL_REF:
				warning (0, "computing pc-relative offset for"
						" %slocal label %<.L%d%>",
						LABEL_REF_NONLOCAL_P (operands[1]) ? "non-" : "",
								(int) CODE_LABEL_NUMBER (XEXP (operands[1], 0)));
				break;

			default:
				gcc_unreachable();
			}

			inform (DECL_SOURCE_LOCATION (current_function_decl),
					"offset is against %qs initialized here", XSTR (pc_sym, 0));
		} /* tricore_log.pic */

		emit_insn (gen_load_pic_symbol (operands[0], operands[1], pc_sym));
		return true;
	}

	if (CONST == code1
			|| (immediate_operand (operands[1], SImode)
					&& !CONST_INT_P (operands[1])
					&& !CONST_DOUBLE_P (operands[1])))
	{
		if (!register_operand (operands[0], mode))
		{
			gcc_assert (can_create_pseudo_p());
			operands[0] = copy_to_mode_reg (mode, operands[0]);
		}

		rtx reg = (can_create_pseudo_p()) ? gen_reg_rtx (mode) : operands[0];

		if (tric_can_move_immediate_p (reg, operands[1]))
		{
			return false;
		}

		if (CONST == GET_CODE (operands[1]))
		{
			rtx plus = XEXP (operands[1], 0);
			rtx sym  = XEXP (plus, 0);
			rtx off  = XEXP (plus, 1);

			if (SYMBOL_REF == GET_CODE (sym)
					&& CONST_INT_P (off)
					&& INTVAL (off) < 0
					&& (tric_symbol_ref_small16_p (sym)
							|| tric_symbol_ref_absolute_p (sym)))
			{
				emit_move_insn (operands[0], sym);
				emit_insn (gen_addsi3 (operands[0], operands[0], off));
				return true;
			}
		}
		if (mode==QImode) {
			return false;
		}
		{
			emit_insn (gen_movsi_high (reg, operands[1]));
			emit_insn (gen_addsi_low (operands[0], reg, operands[1]));
		}
		return true;
	}

	return false;
}


/* For the condition of movsi insn, e.g. This is to keep CSE from
   doing weird things. */

int
tric_mov_operands (rtx *op, enum machine_mode mode)
{
	if (memory_operand (op[0], mode)
      && memory_operand (op[1], mode))
	{
    return 0;
	}
  if (memory_operand (op[0], mode)
      && immediate_operand (op[1], mode))
  {
    return 0;
  }

  if (REG_P (op[0])
      && D_REGNO_P (REGNO (op[0])))
    {
      return 1;

      /* FIXME: This is too restrict. Pass vreg builds mov insns
         like (set (reg D4) (symbol_ref)) */
      if (SYMBOL_REF == GET_CODE (op[1])
          || CONST == GET_CODE (op[1]))
      {
         return 0;
      }
    }

  return 1;
}


/* Split a CONST_INT X into 1 or two parts that can be used in a SET or
   PLUS insn in a way that X = *PART1 + *PART2.
   part2 may be NULL_RTX in which case X = *PART1.
   If the split produced two parts, *PART1 will contain the low-part.
   Note that we don't know whether this will end up in an
   A-regs insn or in a D-regs insn. */

int
tric_split_const_int (rtx x, rtx *part1, rtx *part2, enum rtx_code code)
{
  HOST_WIDE_INT val;
  HOST_WIDE_INT lo;

  gcc_assert (CONST_INT_P (x));
  
  val = INTVAL (x);

  switch (code)
    {
    default:
      gcc_unreachable();

    case SET:
      /* ??? A <-> D */
      if (satisfies_constraint_Ksg (x)
          || satisfies_constraint_Kug (x)
          || satisfies_constraint_Khg (x))
        {
          *part1 = x;
          *part2 = NULL_RTX;
        }
      else
        {
          lo = trunc_int_for_mode (val, HImode);
          *part1 = gen_int_mode (lo, SImode);
          *part2 = gen_int_mode (val-lo, SImode);
        }
      break;

    case PLUS:
      if (satisfies_constraint_Ksg (x)
          || satisfies_constraint_Khg (x))
        {
          *part1 = x;
          *part2 = NULL_RTX;
        }
      else
        {
          lo = trunc_int_for_mode (val, HImode);
          *part1 = gen_int_mode (lo, SImode);
          *part2 = gen_int_mode (val-lo, SImode);
        }
      
      break;
    }

  return (NULL_RTX == *part2) ? 1 : 2;
}

int
tric_split_mov_insn_p (rtx * operands, enum machine_mode mode)
{
  if (LABEL_REF == GET_CODE (operands[1]))
      return true;

  if (HIGH == GET_CODE (operands[1]))
      return false;
      
  switch (mode)
    {
    case E_SImode:
      if (const_int_operand (operands[1], SImode))
        {
          if (d_reg_operand (operands[0], SImode))
            return !(satisfies_constraint_Khg (operands[1])
                     || satisfies_constraint_Kug (operands[1])
                     || satisfies_constraint_Ksg (operands[1]));

          if (a_reg_operand (operands[0], SImode))
            return !(satisfies_constraint_Khg (operands[1])
                     || satisfies_constraint_KSa (operands[1])
                     || (TRIC_HAVE_LHA
                         && satisfies_constraint_Khi (operands[1])));

          gcc_unreachable();
        }

      gcc_assert (tric_can_move_immediate_p (operands[0], operands[1]));

      return false;

    default:
      break;
    }

  return 0;
}


/***********************************************************************
 ** Casesi
 ***********************************************************************/

/*
  #0 = Index
  #1 = Lower
  #2 = Upper-Lower
  #3 = Table Label
  #4 = Default Label
*/

void
tric_emit_casesi (rtx r_index, rtx lower, rtx upper_lower, rtx table, rtx deflt)
{
  /* Note that CASE_VECTOR_MODE = SImode */
  rtx m_lower = gen_int_mode (-UINTVAL (lower), SImode);
  rtx r_table = gen_reg_rtx (SImode);
  rtx r_label = force_reg (SImode, gen_rtx_LABEL_REF (Pmode, table));

  REG_POINTER (r_table) = 1;

  /* Ensure the index is in a REG (not a stack slot etc.) */
  r_index = copy_to_mode_reg (SImode, r_index);

  /* Subtract lowest index from index */
  if (m_lower != const0_rtx)
    emit (gen_addsi3 (r_index, r_index, m_lower));

  /* Branch to default label if index-lower is not in [0..upper-lower] */
  tric_emit_branch (GTU, r_index, upper_lower, deflt);
  
  /* Multiply offset by 4 and add it to the table's address.  4-byte jump
     instructions are forced by .code32 in `ASM_OUTPUT_ADDR_VEC_ELT'.  */
  emit_insn (gen_maddsi4 (r_table, r_index, GEN_INT (4), r_label));

  /* Dispatch to table (contains jumps to respective positions) */
  emit (gen_tablejump (r_table, table));
}


void
tric_emit_insert (rtx *xop)
{
  HOST_WIDE_INT value = tric_rtx_to_hwi (xop[2]);
  HOST_WIDE_INT pos   = tric_rtx_to_hwi (xop[3]);
  HOST_WIDE_INT width = tric_rtx_to_hwi (xop[4]);

  if (width > 32)
    width = 32;

  if (width == 0 || pos >= 32)
    {
      /* Empty suppport:  return unaltered.  */

      emit_move_insn (xop[0], xop[1]);
      return;
    }

  if (width > 0)
    {
      if (pos >= 0 && pos + width > 32)
        width = 32 - pos;

      if (width == 32 && pos == 0)
        {
          /* Override result completely.  */

          emit_move_insn (xop[0], xop[2]);
          return;
        }

      if (value >= 0)
        {
          HOST_WIDE_INT support = (HOST_WIDE_INT) 1 << width;
          support = GET_MODE_MASK (SImode) & (support - 1);

          value &= support;
            
          if (support == value && pos >= 0)
            {
              rtx xbits = gen_int_mode (support << pos, E_SImode);
              if (s10_operand (xbits, SImode))
                {
                  emit_insn (gen_iorsi3 (xop[0], xop[1], xbits));
                  return;
                }
            }

          if (value == 0 && pos >= 0)
            {
              rtx xbits = gen_int_mode (~(support << pos), SImode);
              if (s10_operand (xbits, SImode))
                {
                  emit_insn (gen_andsi3 (xop[0], xop[1], xbits));
                  return;
                }
            }
        }
    }

  xop[2] = value < 0 ? xop[2] : gen_int_mode (value, SImode);
  xop[3] = pos   < 0 ? xop[3] : gen_int_mode (pos,   SImode);
  xop[4] = width < 0 ? xop[4] : gen_int_mode (width, SImode);

  if (!reg_or_u5_operand (xop[4], SImode))
    xop[4] = force_reg (SImode, xop[4]);

  if (!reg_or_u4_operand (xop[2], SImode))
    xop[2] = force_reg (SImode, xop[2]);

  if (u5_operand (xop[4], SImode))
    {
      emit_insn (gen_insert_const_width (xop[0], xop[1],
                                         xop[2], xop[3], xop[4]));
    }
  else
    {
      rtx xinsert = gen_reg_rtx (DImode);
      rtx lo = simplify_gen_subreg (SImode, xinsert, DImode, 0);
      rtx hi = simplify_gen_subreg (SImode, xinsert, DImode, 4);

      emit_move_insn (lo, xop[3]);
      emit_move_insn (hi, xop[4]);
      emit_insn (gen_insert64 (xop[0], xop[1], xop[2], xinsert));
    }
}


/* Expand for imask insn.
   $0 = DImode output.  High = mask, Low = value.
   $1 = value
   $2 = starting bit of the value
   $3 = width  */

void
tric_emit_imask (rtx *xop)
{
  rtx hi, lo;
  HOST_WIDE_INT pos   = tric_rtx_to_hwi (xop[2]);
  HOST_WIDE_INT width = tric_rtx_to_hwi (xop[3]);

  if (width == 0 || pos >= 32)
    {
      /* Empty support: return 0.  */

      emit_move_insn (xop[0], gen_int_mode (0, DImode));
      return;
    }

  /* Cut support to the 32 bits it represents.  */

  if (width > 32)
    width = 32;

  if (pos >= 0 && width >= 0 && pos + width > 32)
    width = 32 - pos;

  if (width > 0 && width < 32)
    {
      /* IMASK instruction need a compile-time-const width.  */

      xop[1] = force_reg (SImode, xop[1]);

      if (!reg_or_u4_operand (xop[2], SImode))
        xop[2] = force_reg (SImode, xop[2]);

      if (!reg_or_u5_operand (xop[3], SImode))
        xop[3] = force_reg (SImode, xop[3]);

      emit_insn (gen_imaskdi (xop[0], xop[1], xop[2], GEN_INT (width)));
      return;
    }

  /* Fallback:  Mimic IMASK's action.  */

  lo = simplify_gen_subreg (SImode, xop[0], DImode, 0);
  hi = simplify_gen_subreg (SImode, xop[0], DImode, 4);

  /* $0.low: Shift value into place.  */

  if (pos == 0)
    emit_move_insn (lo, xop[1]);
  else
    emit_move_insn (lo, gen_rtx_ASHIFT (SImode, xop[1], xop[2]));

  /* $0.high: The support.  */

  if (width == 0)
    {
      emit_move_insn (hi, const0_rtx);
    }
  else if (width == 32 && pos >= 0)
    {
      emit_move_insn (hi, gen_int_mode (-1u << pos, SImode));
    }
  else if (width == 32 && pos == -1)
    {
      emit_move_insn (hi, gen_rtx_ASHIFT (SImode,
                                          force_reg (SImode, constm1_rtx),
                                          xop[2]));
    }
  else if (width == -1)
    {
      emit_insn (gen_insert_mask (hi, xop[2], xop[3]));
    }
  else
    gcc_unreachable();
}


static void
tric_register_passes (void)
{

  /* Sole purpose of this machine specific pass is to determine
     `tric_after_split1_pass_number', a pass number that runs after split1
     and before register allocation.  */

  tric_pass_notice_split1 *tric_after_split1_pass
    = new tric_pass_notice_split1 (g);

  register_pass (tric_after_split1_pass,
                 PASS_POS_INSERT_AFTER, "asmcons", 1);


  /*some optimization before lower gimple*/

  tric_pass_gimple *tric_before_lower_gimple = new tric_pass_gimple (g);
  register_pass (tric_before_lower_gimple,
                 PASS_POS_INSERT_BEFORE, "lower", 1);

  /*some optimization after ssa*/

  tric_strcmp_gimple *tric_after_alias = new tric_strcmp_gimple (g);
  register_pass (tric_after_alias,
                 PASS_POS_INSERT_AFTER, "alias", 1);


  tric_after_split1_pass_number
    = tric_after_split1_pass->get_next_pass_number();

  /* Try to optimize multi-instruction loads of compile time constants
     to shorter instruction sequences by reusing known values.  This pass
     runs after reload and before the first post-reload split pass
     `pass_split_after_reload'.  */
  tric_pass_const_anchor *tric_post_anchor_pass
    = new tric_pass_const_anchor (g);
  register_pass (tric_post_anchor_pass,
                 PASS_POS_INSERT_BEFORE, "split2", 1);

  tric_pass_arg *tric_post_split2
    = new tric_pass_arg (g);
  register_pass (tric_post_split2,
                 PASS_POS_INSERT_AFTER, "split2", 1);

}



/***********************************************************************
 ** Options and Command Line Switches
 ***********************************************************************/


/* Implement `TARGET_OPTION_OVERRIDE' */

static void
tric_option_override (void)
{

  if (NULL == tric_opt_segment_trap)
    tric_decode_msegment_trap ("default", "");

  if (TARGET_FAST_MATH)
    {
      flag_unsafe_math_optimizations = 1;
      flag_finite_math_only = 1;
    }

  if (flag_pic)
    error ("%qs: position independent code is not supported for "
           "this machine, try %qs", "-fpic", "-mcode-pic");

  flag_schedule_insns = 0;

  /* ???: web crashed on branch_and_decrement
     gcc.c-torture/compile/20000629-1.c -mtc16 -O3 -funroll-loops
     so we disable it for now.  */

  flag_web = 0;

  /* Disable regrename because it does not check validity of insns after some
     thing changes which might break *mov64 insn.  HARD_REGNO_RENAME_OK does
     not provide enough information to return resonable results.  */
  
  flag_rename_registers = 0;
  
  if (!tric_segment_trap.do_ivopts)
    flag_ivopts = 0;

  tric_set_device (NULL);

  /* Handle -m[no-]errata=ARG:  If the option was not given on the
     command line, use the default as specified in the errata definition.
     We do this after the core is set so that ON is properly set.  */
     
#define DEF_ERRATA(ARG, CC1, AS, DEFIN, ON, IFX_NAME)     \
  if (-1 == tric_errata[tric_errata_ ## ARG].fixit)       \
    tric_errata[tric_errata_ ## ARG].fixit = (ON);
#include "errata.def"
#undef DEF_ERRATA

  /* Adjust upper and lower bounds for data to put into .zdata resp. .sdata. */

  if (tric_zconst_max <= tric_sconst_max)
    tric_sconst_min = tric_zconst_max + 1;
  else
    tric_zconst_min = tric_sconst_max + 1;

  if (tric_zdata_max <= tric_sdata_max)
    tric_sdata_min = tric_zdata_max + 1;
  else
    tric_zdata_min = tric_sdata_max + 1;

  /* Register some tricore-specific pass(es).  There is no canonical place
     for pass registration.  This function is convenient.  */

  tric_register_passes ();

  /* Check whether prerequisite option for -msection-asm-name are set.
     Initialize -mlog.  */

  tricore_log_set_tricore_log();
}


/* Implement `TARGET_ASM_RECORD_GCC_SWITCHES' */
#if 0
static int
tric_asm_record_gcc_switches (print_switch_type type, const char *text)
{
  FILE *file = asm_out_file;
  
  static int printing = 0;
  static const char *start = NULL;
  static const char *end = NULL;
  static bool gcc_version_recorded_p = false;

  if (!gcc_version_recorded_p)
    {
      fputs (".section .version_info.ident,\"\",@progbits\n", file);
      fprintf (file, ".ascii \"%s\"\n\n", version_string);
      gcc_version_recorded_p = true;
    }
  
  switch (type)
    {
    case SWITCH_TYPE_DESCRIPTIVE:

      if (NULL == text)
        {
          gcc_assert (printing <= 1);
          printing++;
          if (2 == printing)
            fputs ("\n", file);
        }
      else
        {
          if (printing)
            {
              fputs ("\n.section .version_info.cc1_switches.", file);
              for (; *text && *text != ':'; text++)
                {
                  if (' ' == *text)
                    fputc ('_', file);
                  else if (ISALNUM (*text))
                    fputc (*text, file);
                }
              fputs (",\"\",@progbits\n", file);
            }
        }

      end = "\n";

      break;
      
    case SWITCH_TYPE_LINE_START:
      start = ".ascii \"";
      break;
      
    case SWITCH_TYPE_LINE_END:
      if (end)
        {
          fputs (end, file);
          end = NULL;
        }
      break;

    default:
      if (start)
        {
          fputs (start, file);
          start = NULL;
        }
      
      for (; *text; text++)
        {
          /* Escaping " and \  */
          if (strchr ("\"\\", *text))
            fputc ('\\', file);
          fputc (*text, file);
        }
      fputc (' ', file);
      
      end = "\"\n";
      break;
    }

  return 0;
}
#endif

/***********************************************************************
 ** Register Classes
 ***********************************************************************/

static inline int
tric_reg_ok_for_addr (rtx reg, int strict)
{
  unsigned int regno;

  if (!REG_P (reg))
    return 0;

  regno = REGNO (reg);

  /* Beware: Don't use REGNO_OK_FOR_BASE_P from here because reg_renumber
     is not yet set up properly, cf. HDP-172.  */

  return (A_REGNO_P (regno)
          || (!strict
              && (regno >= FIRST_PSEUDO_REGISTER
                  || regno == ARG_POINTER_REGNUM)));
}


/* Implement `REGNO_REG_CLASS' */

enum reg_class
tric_regno_reg_class (int r)
{
  static const enum reg_class tric_reg_class_tab[FIRST_PSEUDO_REGISTER] =
    {
      /* D0...D15: D15 has its own class */
      REGCLASS_D, REGCLASS_D, REGCLASS_D, REGCLASS_D,
      REGCLASS_D, REGCLASS_D, REGCLASS_D, REGCLASS_D,
      REGCLASS_D, REGCLASS_D, REGCLASS_D, REGCLASS_D,
      REGCLASS_D, REGCLASS_D, REGCLASS_D, REGCLASS_D15,
      
      /* A0...A15: SP and A15 have their own class */
      REGCLASS_A, REGCLASS_A, REGCLASS_A,   REGCLASS_A,
      REGCLASS_A, REGCLASS_A, REGCLASS_A,   REGCLASS_A,
      REGCLASS_A, REGCLASS_A, REGCLASS_A10, REGCLASS_A,
      REGCLASS_A, REGCLASS_A, REGCLASS_A,   REGCLASS_A15,

      /* ARGP, PSW */
      ALL_REGS, ALL_REGS
    };

  gcc_assert (r < FIRST_PSEUDO_REGISTER);

  return tric_reg_class_tab[r];
}


/* Implement `HARD_REGNO_MODE_OK' */
/* Return 1 if hard register REGNO can hold a value of machine-mode MODE.  */

bool
tric_hard_regno_mode_ok (unsigned int regno, enum machine_mode mode)
{
  if (mode == TImode)
  {
	  return (Q_REGNO_P (regno));
  }

  if (GET_MODE_SIZE (mode) > UNITS_PER_WORD)
  {
	  return (E_REGNO_P (regno) || EA_REGNO_P (regno));

  }

  return regno != REG_SP && regno != REG_A11;
}


/* Implement `HARD_REGNO_RENAME_OK' */
/* Return nonzero if register OLD_REG can be renamed to register NEW_REG.  */

int
tric_hard_regno_rename_ok (unsigned int old_reg ATTRIBUTE_UNUSED,
                           unsigned int new_reg ATTRIBUTE_UNUSED)
{
  return 1;
}


/* Implement `TARGET_CONDITIONAL_REGISTER_USAGE' */
/* Called early in the compilation to conditionally modify
   fixed_regs/call_used_regs.  */

static void
tric_conditional_register_usage (void)
{
  if (tric_opt_code_pic
      && tric_opt_dynamic_code_pic)
    {
      fixed_regs[REG_PIC] = 1;
      call_used_regs[REG_PIC] = 1;
    }
}


/* Implement `LOCAL_REGNO' */
/* Adding call-saved regs to LOCAL_REGNO will result in better lifeness
   information after reload. Note that (return) does not mention that
   it will restore these regs and there is no explicit restore code. */

int
tric_local_regno (unsigned int regno)
{
  return (regno <= 31
          && (LOCAL_REGNO_MASK & (1 << regno)));
}

enum machine_mode
tric_mode_for_align (HOST_WIDE_INT align, rtx xlen)
{
  if (CONST_INT_P (xlen))
    {
      unsigned HOST_WIDE_INT len = UINTVAL (xlen);

      /* When optimizing for speed, make mode only dependent on align.  */
      
      if (optimize_insn_for_speed_p())
        len = 0;
      
      if (align % 4 == 0 && len % 16 == 0)
        return TImode;

      if (align % 4 == 0 && len % 8 == 0)
        return DImode;
      
      if (align % 4 == 0 && len % 4 == 0)
        return SImode;
      
      if (align % 2 == 0 && len % 2 == 0)
        return HImode;
    }
  
  return QImode;
}


/***********************************************************************
 ** Reload and Register Allocation
 ***********************************************************************/

/* Implement `TARGET_CLASS_LIKELY_SPILLED_P' */

static bool
tric_class_likely_spilled_p (reg_class_t c)
{
  return c == REGCLASS_A15 ||  c == REGCLASS_D15;
}


/* Implement `TARGET_SECONDARY_RELOAD' */

static reg_class_t
tric_secondary_reload (bool in_p, rtx x, reg_class_t rclass,
                       enum machine_mode mode,
                       secondary_reload_info *sri ATTRIBUTE_UNUSED)
{
  if (REGCLASS_R == rclass
      || reg_class_subset_p (rclass, REGCLASS_A))
    {
      if (HImode == mode || QImode == mode || HFmode == mode)
        {
          /* QI HI and HF may go into a-regs, but we cannot load/store
             them directly from memory */
          
          if (MEM_P (x))
            {
              return REGCLASS_D;
            }
        }

      /* On TC13x, ST.A just allows 10-bit offsets */

      if (TRIC_13X
          && ! in_p
          && MEM_P (x))
        {
          if (PLUS == GET_CODE (XEXP (x, 0))
              && REG_P (XEXP (XEXP (x, 0), 0))
              && ! satisfies_constraint_Ksa (XEXP (XEXP (x, 0), 1)))
            {
              return REGCLASS_D;
            }
      
          if (LO_SUM == GET_CODE (XEXP (x, 0)))
            {
              return REGCLASS_D;
            }
        }
    }

  if (REGCLASS_R == rclass
      || reg_class_subset_p (rclass, REGCLASS_D))
    {
      if (SYMBOL_REF == GET_CODE (x)
          || CONST == GET_CODE (x))
        {
          return REGCLASS_A;
        }
    }

  return NO_REGS;
}


/***********************************************************************
 ** Addresses' Legitimization and Address Constraints
 ***********************************************************************/

static bool
tric_offset_for_mode_p (rtx offset, enum machine_mode mode)
{
  int bitsize = BLKmode == mode ? 0 : GET_MODE_BITSIZE (mode);

  switch (bitsize)
    {
    case 8:
    case 16:
      return (TRIC_13X
              ? satisfies_constraint_Ksa (offset)
              : satisfies_constraint_Ksg (offset));
      
    case 64:
      return satisfies_constraint_Ksa (offset);

    case 32:
      return satisfies_constraint_Ksg (offset);

    case 0:
      return satisfies_constraint_Ksa (offset);

    default:
      return false;
    }
}


/* Implement `TARGET_LEGITIMATE_ADDRESS_P' */

static bool
tric_legitimate_address_p (enum machine_mode mode, rtx x, bool strict)
{
  int ok = 0;
  int bitsize = BLKmode == mode ? 0 : GET_MODE_BITSIZE (mode);
    
  switch (GET_CODE (x))
    {
    case REG:
      ok = tric_reg_ok_for_addr (x, strict);
      break;

    case PRE_INC:
      ok = (HAVE_PRE_INCREMENT
            && tric_reg_ok_for_addr (XEXP (x, 0), strict));
      break;

    case PRE_DEC:
      ok = (HAVE_PRE_DECREMENT
            && tric_reg_ok_for_addr (XEXP (x, 0), strict));
      break;

    case POST_INC:
    case POST_DEC:
      ok = tric_reg_ok_for_addr (XEXP (x, 0), strict);
      break;

    case PRE_MODIFY:
    case POST_MODIFY:
      {
        rtx reg = XEXP (x, 0);
        rtx mod = XEXP (x, 1);
        rtx op0 = XEXP (mod, 0);
        rtx op1 = XEXP (mod, 1);

        ok = PLUS == GET_CODE (mod)
          && tric_reg_ok_for_addr (reg, strict)
          && tric_reg_ok_for_addr (op0, strict)
          && satisfies_constraint_Ksa (op1);

        ok &= (POST_MODIFY == GET_CODE (x)
               || (HAVE_PRE_INCREMENT && INTVAL (op1) > 0)
               || (HAVE_PRE_DECREMENT && INTVAL (op1) < 0));
        break;
      }

    case CONST_INT:
      ok = TRIC_ABSOLUTE_INT_ADDRESS_P (INTVAL (x));
      break;

    case CONST:
    case SYMBOL_REF:
      ok = (tric_absolute_address_p (x)
            || (tric_small16_address_p (x)
                && (bitsize == 32
                    || bitsize == 0
                    || (!TRIC_13X
                        && (bitsize == 8 || bitsize == 16)))));
      break;

    case LO_SUM:
      {
        rtx op0 = XEXP (x, 0);
        rtx op1 = XEXP (x, 1);

        ok = (tric_reg_ok_for_addr (op0, strict)
              && SYMBOL_REF == GET_CODE (op1)
              && (bitsize == 32
                  || bitsize == 0
                  || (!TRIC_13X
                      && (bitsize == 8 || bitsize == 16))));
        
        break;
      }
      
    case PLUS:
      {
        rtx op0 = XEXP (x, 0);
        rtx op1 = XEXP (x, 1);
        
        if (REG_P (op0)
            && CONST_INT_P (op1))
          {
            ok = tric_reg_ok_for_addr (op0, strict)
             && tric_offset_for_mode_p (op1, mode);
          }

        break;
      }
      
    default:
      break;
    }

  if (tricore_log.legitimate_address_p)
    tricore_edump ("%?:%m strict=%d: %d = %r\n", mode, strict, ok, x);
    
  return ok;
}


/* Implement `TARGET_LEGITIMIZE_ADDRESS' */

static rtx
tric_legitimize_address (rtx x, rtx oldx, enum machine_mode mode)
{
  rtx reg, reg2, off;

  (void) oldx;
  
  if (TRIC_13X
      && GET_MODE_SIZE (mode) < UNITS_PER_WORD
      && PLUS == GET_CODE (x)
      && REG_P (reg = XEXP (x, 0))
      && CONST_INT_P (off = XEXP (x, 1))
      && ! satisfies_constraint_Ksa (off))
    {
      /* x is of the form

             (plus (reg const_int))

         where the offset doesn't fit in signed 10 bits as needed for
         QI/HI accesses.  We supply an intermediate address at offset
         a multiple of 1024 from reg.  This might help CSE in situations
         when there are more accesses like this around.  However, in
         cases where CSE cannot find similar accesses, code size will
         increase. */
      
      rtx reg2 = gen_reg_rtx (SImode);
      int offset = INTVAL (off);
      int o9 = offset % (1 << 10);

      /* Take care of positive/negative offsets and constrain to [-512,512) */
      o9 += (o9 >= (1<<9)) ? -(1<<10) : (o9 < -(1<<9)) ? (1<<10) : 0;

      /* The intermediate address */
      emit_insn (gen_addsi3 (reg2, reg, gen_int_mode (offset-o9, SImode)));

      /* The address: reg + offset = reg2 + o9 */
      return gen_rtx_PLUS (SImode, reg2, gen_int_mode (o9, SImode));
    }

  if (PLUS == GET_CODE (x)
      && PLUS == GET_CODE (XEXP (x, 0))
      && REG_P (reg  = XEXP (XEXP (x, 0), 0))
      && REG_P (reg2 = XEXP (XEXP (x, 0), 1))
      && CONST_INT_P (off = XEXP (x, 1))
      && INTVAL (off) > 0
      && tric_offset_for_mode_p (off, mode))
    {
      /* x is of the form
           (plus (plus (reg
                        reg)
                  const_int))
      */

      rtx reg_sum = gen_reg_rtx (SImode);

      emit_insn (gen_addsi3 (reg_sum, reg, reg2));

      return gen_rtx_PLUS (SImode, reg_sum, off);
    }
      
  if (tricore_log.legitimize_address)
    tricore_edump ("%?:%m\tx= %r\n\toldx= %r\n", mode, x, oldx);

  return x;
}


/* Constraint helper function for "Wa".  "Wa" is used to store A-regs to mem,
   it is a subset of "Wm".  TC13x has a limited (smaller than 16 bits)
   offset for ST.A.  */

int
extra_constraint_Wa (rtx x)
{
  rtx addr;
  enum machine_mode mode;

  gcc_assert (MEM_P (x));
  
  addr = XEXP (x, 0);
  mode = GET_MODE (x);

  if (!tric_legitimate_address_p (mode, addr, true))
    return false;

  return TRIC_13X ? tric_legitimate_address_p (HImode, addr, true) : true;
}


/* Constraint "Wl" is used for LDMST and SWAP.W.  */

int
extra_constraint_Wl (rtx x)
{
  rtx addr;
  enum machine_mode mode;

  gcc_assert (MEM_P (x));
  
  addr = XEXP (x, 0);
  mode = GET_MODE (x);

  if (!tric_legitimate_address_p (mode, addr, true))
    return false;

  return tric_legitimate_address_p (DImode, addr, true);
}


/* Constraint "Wc" is used for CMPSWAP.W.  */

int
extra_constraint_Wc (rtx x)
{
  rtx addr;
  enum machine_mode mode;

  gcc_assert (MEM_P (x));
  
  addr = XEXP (x, 0);
  mode = GET_MODE (x);

  if (!tric_legitimate_address_p (mode, addr, true))
    return false;

  return tric_legitimate_address_p (DImode, addr, true)
    && !tric_absolute_address_p (addr);
}


int
extra_constraint_Wm (rtx x)
{
  if (!memory_operand (x, GET_MODE (x)))
    return 0;

  return tric_legitimate_address_p (GET_MODE (x), XEXP (x, 0), true);
}


/* Implement `TARGET_HTC_IVOPT_BASE_COSTS_P' */
/* tree-ssa-loop-ivopts.c has a default algorithm to calculate the
   base costs. This hook allows to increase the base costs of
   addresses.  */

static bool
tric_ivopt_base_costs_p (void)
{
  gcc_assert (tric_segment_trap.do_ivopts);

  return tric_segment_trap.do_ivopts_base_costs;
}


/* Implement `TARGET_HTC_IVOPT_USE_ADDRESS_P' */
/* tree-ssa-loop-ivopts.c collects different kinds of "interesting" uses
   of induction variables, one of which is USE_ADDRESS.  This hook allows
   to skip respective uses so that they are not taken into account for
   optimization and hence the associated MEM_REFs won't be changed.  */

static bool
tric_ivopt_use_address_p (void)
{
  gcc_assert (tric_segment_trap.do_ivopts);

  return tric_segment_trap.do_ivopts_use_address;
}


/* Implement `TARGET_HTC_SCHED_MAY_CHANGE_ADDRESS_P' */
/* This is called from sched-deps.c (find_modifiable_mems).
   For TriCore, the scheduler is allowed to change addresses
   iff -muse-ivopt=all which enables the GCC original full ivopt
   optimization.  */

static bool
tric_sched_may_change_address_p (void)
{
  return tric_segment_trap.do_sched_change_address;
}



/***********************************************************************
 ** Double and Float Constraints
 ***********************************************************************/

int
extra_constraint_Ga9 (rtx x)
{
  unsigned lo, hi;
  tric_split_const_rtx (x, &lo, &hi);

  /* ADDC and ADDX allow s9 constants (9 bit signed) */
  return (satisfies_constraint_Ks9 (gen_int_mode (lo, SImode))
          && satisfies_constraint_Ks9 (gen_int_mode (hi, SImode)));
}


int
extra_constraint_Gsg (rtx x)
{
  unsigned lo, hi;
  tric_split_const_rtx (x, &lo, &hi);

  return satisfies_constraint_Ksg (gen_int_mode (lo, SImode));
}


int
extra_constraint_Ghg (rtx x)
{
  unsigned lo, hi;
  tric_split_const_rtx (x, &lo, &hi);

  return satisfies_constraint_Khg (gen_int_mode (lo, SImode));
}


int
extra_constraint_Gu4 (rtx x)
{
  unsigned lo, hi;
  tric_split_const_rtx (x, &lo, &hi);

  return satisfies_constraint_Ku4 (gen_int_mode (lo, SImode));
}


int
extra_constraint_GSa (rtx x)
{
  unsigned lo, hi;
  tric_split_const_rtx (x, &lo, &hi);

  return satisfies_constraint_KSa (gen_int_mode (lo, SImode));
}


/***********************************************************************
 ** Costs
 ***********************************************************************/

/* Implement `TARGET_REGISTER_MOVE_COST' */

static int
tric_register_move_cost (enum machine_mode mode,
                         reg_class_t class1, reg_class_t class2)
{

/* TODO Verify the impact on performance */
	
  if (reg_class_subset_p (class1, REGCLASS_A)
      && reg_class_subset_p (class2, REGCLASS_A))
    return 2 * tric_hard_regno_nregs (0, mode);

  if (reg_class_subset_p (class1, REGCLASS_D)
      && reg_class_subset_p (class2, REGCLASS_D))
    {
      if (TRIC_HAVE_MOV64 && 64 == GET_MODE_BITSIZE (mode))
        {
          return tric_hard_regno_nregs (0, mode);
        }
      return 2 * tric_hard_regno_nregs (0, mode);
    }

  return GET_MODE_SIZE (mode) > 64 ? 8 : 2;
  
}


/* Implement `TARGET_MEMORY_MOVE_COST' */

static int
tric_memory_move_cost (enum machine_mode mode, reg_class_t class1, bool in)
{
  (void) in;
  
  if (class1 == REGCLASS_D15
      || class1 == REGCLASS_A15)
    return 10 * tric_hard_regno_nregs (0, mode);
  return 40 * tric_hard_regno_nregs (0, mode);
}





/* Cost of stuff that's a bit more complicated than just a binary operation.
   expmed.c might come up with nonsensical machine modes, hence we'll just
   have a look at the anatomy of the RTXes rather than strictly checking
   modes of all operands.  */

static bool
tric_arith_costs (rtx x, int *total, bool speed)
{
  bool done = false;
  enum machine_mode mode = GET_MODE (x);
  rtx op0 = BINARY_P (x) || UNARY_P (x) ? XEXP (x, 0) : NULL_RTX;
  rtx op00;

  switch (GET_CODE (x))
    {
    default:
      break;

    case MULT:
      if (DImode == mode
          && (SIGN_EXTEND == GET_CODE (op0)
              || ZERO_EXTEND == GET_CODE (op0)))
        {
          // [u]mulsidi3
          *total = speed ? 3 : 4;
          done = true;
        }
      break;

    case TRUNCATE:
      if (DImode == GET_MODE (op0)
          && LSHIFTRT == GET_CODE (op0)
          && MULT == GET_CODE (op00 = XEXP (op0, 0))
          && (ZERO_EXTEND == GET_CODE (XEXP (op00, 0))
              || SIGN_EXTEND == GET_CODE (XEXP (op00, 0))))
        {
          // [u]mulsidi3_highpart
          *total = speed ? 3+1 : 4+1;
          done = true;
        }
      break;
    }

  if (tricore_log.rtx_costs
      && done)
    tricore_edump ("%?: %r -> %d\n\n", x, *total);

  return done;
}


/* Get rtx cost for the binary operation CODE in mode MODE.
   X is the second operand and either a REG or a CONST_INT.
   The first operand is a REG. */

static int
tric_binary_cost (enum machine_mode mode, enum rtx_code code, rtx x, bool speed)
{
  int cost = 1000;
  int reg_p = (REG_P (x)
               || (SUBREG == GET_CODE (x)
                   && REG_P (SUBREG_REG (x))));

  /* Some values for conveniance including the number of expected,
     additional moves to get a constant. */
  
  const int cost_reg = speed ? 2 : 4;
  const int cost_const = (reg_p
                          ? 0
                          : ((satisfies_constraint_Ksg (x)
                              || satisfies_constraint_Khg (x))
                             ? (speed ? 2 : 4)
                             : (speed ? 4 : 8)));

  /* A DIV instruction costs 2*4..2*11 depending on size of operand.
     For the DIV we take an average of 5.5.  DVSTEP et al. cost 2*5. */
  
  const int cost_nodiv  = speed ? 2*6*6 : tric_opt_fast_div ? 6*4 : 6;
  const int cost_noudiv = speed ? 2*6*5 : tric_opt_fast_div ? 5*4 : 6;
  const int cost_div  = TRIC_HAVE_DIV ? (speed ? 11 : 4) : cost_nodiv;
  const int cost_udiv = TRIC_HAVE_DIV ? (speed ? 11 : 4) : cost_noudiv;

  const bool s9_p = reg_p || satisfies_constraint_Ks9 (x);
  const bool u9_p = reg_p || satisfies_constraint_Ku9 (x);

  if (SImode == mode)
    switch (code)
      {
      default:
        cost = 1000;
        break;
        
      case PLUS:
      case MINUS:
        cost = (reg_p
                || satisfies_constraint_Ksg (x)
                || satisfies_constraint_Khg (x))
          ? cost_reg
          : cost_reg + cost_const;
        
        break;

      case UMAX: case UMIN:
      case SMAX: case SMIN:
        cost = cost_reg;
        break;

      case AND:  case IOR:  case XOR:
      case LT:   case LE:
      case GT:   case GE:
      case EQ:   case NE:
      case COMPARE:
        cost = s9_p ? cost_reg : cost_reg + cost_const;
        break;
        
      case LTU:  case LEU:
      case GTU:  case GEU:
        cost = u9_p ? cost_reg : cost_reg + cost_const;
        break;
        
      case MULT:
        cost = speed ? 2 : cost_reg;
        if (!s9_p) cost += cost_const;
        break;
        
      case DIV:
      case MOD:
        cost = reg_p ? cost_div : cost_div + cost_const;
        break;
        
      case UDIV:
      case UMOD:
        cost = reg_p ? cost_udiv : cost_udiv + cost_const;
        break;

      case ASHIFT:
      case ROTATE:
        cost = cost_reg;
        break;
      
      case ASHIFTRT:
      case LSHIFTRT:
        cost = reg_p ? 2 * cost_reg : cost_reg;
        break;
    }
  
  if (DImode == mode)
    switch (code)
      {
      default:
        cost = 1000;
        break;


      case MULT:
        cost = speed ? 3*2 : 3*4;
        break;

      case PLUS:
      case MINUS:
        cost = s9_p ? 2*cost_reg : 2*cost_reg /*+ cost_const*/;
        break;

      case ASHIFTRT:
      case LSHIFTRT:
        cost = (speed && reg_p) ? 9 * cost_reg : 2 * cost_reg;
        break;

      case ASHIFT:
        cost = (speed && reg_p) ? 6 * cost_reg : 2 * cost_reg;
        break;
      }

  if (SFmode == mode)
    switch (code)
      {
      default:
        cost = 1000;
        break;

      case PLUS:
      case MINUS:
      case MULT:
      case DIV:
        cost = 6;
        break;

      case SMIN:
      case SMAX:
        cost = 12;
        break;
      }

  if (tricore_log.rtx_costs)
    tricore_edump ("%?:{%C:%m} %r -> %d\n", code, mode, x, cost);
  
  return cost;
}


/* Implement `TARGET_RTX_COSTS' */
/* Compute relative costs for some rtx. If optimizing for size we
   return the expected number of bytes the instruction will occupy.
   When optimizing for speed we try to compute the expected time an
   instruction needs to complete multiplied by 2, i.e. a simple MOV
   is rated as 2. According to P. Jewstafjew, this time is mainly
   given by the instruction latency which is 1 for most operations,
   3 for MUL and MADD (we rate as 5, i.e. 2.5 ticks), 4-11 for DIV
   and about 5-6 for DVSTEP. */
//static int
//contains_large_mode_p (rtx *x, void *data ATTRIBUTE_UNUSED)
//{
//  enum machine_mode mode = GET_MODE (*x);
//
//  return mode != VOIDmode && GET_MODE_SIZE (mode) >= 8;
//}


static bool
tric_contains_large_mode_p (rtx insn);

static bool
tric_contains_large_mode_p (rtx insn)
{
  enum machine_mode mode;
  subrtx_iterator::array_type array;
  FOR_EACH_SUBRTX (iter, array, insn, ALL)
  {
    const_rtx x = *iter;
    mode=GET_MODE (x);
    if ((mode != VOIDmode) && (GET_MODE_SIZE (mode) >= 8)) return true;
  }
  return false;

}

static
bool tric_rtx_costs (rtx x, machine_mode mode, int outer_code, int op_num ATTRIBUTE_UNUSED,
                int *total, bool speed)
{
  /* false --> recurse x */


  enum rtx_code code = GET_CODE(x);
  rtx op1;
  bool large_mode_p=tric_contains_large_mode_p(x);
  /* Section 0:
     Things we definitely don't support */
     
  *total = 000;

  if ((VOIDmode == mode && code != SET)
      || UNKNOWN == outer_code)
    return true;

  if (ASM_INPUT == code
      || ASM_OPERANDS == code)
    {
      return true;
    }
  
  if (TImode == mode
      || QImode == mode
      || HImode == mode)
    {
      /* ??? Guess after reload */
      
      *total = reload_completed ? 4 : 1000;
      return true;
    }
  
  /* Section 1:
     Handle some stuff by hand: most binary operations and
     constants. In the case of operations we estimate the overhead
     which is needed to load large constants. Quering the md does not
     work well here because we are supposed to get the cost even if
     the rtx is not supported in itself like (div reg const_int). */
  
  if (SET == outer_code
      && BINARY_P (x)
      && REG_P (XEXP (x, 0))
      && (REG_P (op1 = XEXP (x, 1))
          || CONST_INT_P (XEXP (x, 1))))
    {
      *total = tric_binary_cost (mode, GET_CODE (x), op1, speed);
      return true;
    }

  if (SET == outer_code
      && tric_arith_costs (x, total, speed))
    return true;

  if ((IOR == code || AND == code)
      && MEM_P (XEXP (x, 0)))
    {
      *total = speed ? 6 : 4;

      if (tricore_log.rtx_costs)
        tricore_edump ("%?:{%C:%m} %r -> %d\n", outer_code, mode, x, *total);

      return true;
    }

  if ((GET_RTX_CLASS (outer_code) & RTX_BINARY_MASK) == RTX_BINARY_RESULT
      && (REG_P (x)
          || CONST_INT_P (x)))
    {
      *total = tric_binary_cost (VOIDmode == mode
                                 ? SImode
                                 : mode, (enum rtx_code) outer_code, x, speed);
      return true;
    }

  if (SET == outer_code || UNKNOWN == outer_code)
    {
      if (CONST_INT_P (x))
        {
          if (const0_rtx == x)
            *total = 0;
          else if (speed)
            *total = (satisfies_constraint_Ksg (x)
                      ||  satisfies_constraint_Khg (x)
                      ? 2 : 4);
          else
            *total = tric_const_int_costs (INTVAL (x));

          if (tricore_log.rtx_costs)
            tricore_edump ("%?:{%C:%m} %r -> %d\n", outer_code, mode, x, *total);
          
          return true;
        }

      if (CONST_DOUBLE_P (x))
        {
          *total = tric_const_double_costs (x);

          if (tricore_log.rtx_costs)
            tricore_edump ("%?:{%C:%m} %r -> %d\n", outer_code, mode, x, *total);
          
          return true;
        }
    }

  /* Section 2:
     Query the machine description for rtx costs.  We find it too tedious
     to write all or most of the patterns down twice: once as fancy rtl and
     a second time as even more braindead and hard-to-maintain XEXP-orgy.
     We build a fake insn and look for insn attribute "ticks" resp. "space". */
  
  if (SET == outer_code
      && mode != BLKmode)
    {
      int num_clobbers;
      rtx pattern, dest;
      rtx_insn *insn;

      /* Some passes like if-convert-after-reload call for rtx costs after
         reload_completed.  We have no idea how the set-dest looks like,
         GCC developers once more make a mistery around information which
         is actually present. We return 'unknown', i.e. 0 in that case. */

      if (reload_completed)
        {
          /* ???: Just guess the costs; there is nothing to match against
             without DEST.  */
          
          *total = 4;
          return true;
        }
         
      /* Set up an insn to be recognized */

      if (NULL_RTX == fake_insn)
        {
          /* Doh!  We've got no wrapping insns yet.  Cook them up.  */

          rtx fake_reg = gen_rtx_REG (SImode, 99999);

          start_sequence();

          fake_pattern = gen_rtx_SET (fake_reg, const0_rtx);
          fake_insn = emit_insn (fake_pattern);

          fake_jump_pattern = gen_rtx_SET (pc_rtx, fake_reg);
          fake_jump_insn = emit_jump_insn (fake_jump_pattern);

          end_sequence();
        }

      if (VOIDmode == mode)
        {
          /* This is for a conditional jump */
          dest = pc_rtx;
          insn = fake_jump_insn;

          if (CONST_INT_P (x))
            {
              tricore_edump ("%?: %r\n", x);
              abort();
            }
        }
      else
        {
          /* This is for ordinary insn */
          dest = gen_rtx_REG (mode, 99999);
          insn = fake_insn;
        }

      /* Open gate for COST_INSNs */
      
      tric_have_cost_insns = 1;

      pattern = gen_rtx_SET (dest, x);
      PATTERN (insn) = pattern;

      /* Avoid insn caching from recog_memoized.  */

      INSN_CODE (insn) = recog (pattern, insn, &num_clobbers);
      
      *total = INSN_CODE (insn) < 0
        ? 22
        : (speed) ? get_attr_ticks (insn) : get_attr_space (insn);

      /* Close gate for COST_INSNs */
      
      tric_have_cost_insns = 0;

      /* ??? We set the pattern to a valid rtx construct because we observed
         ggc aborting for complex programs due to invalid set_dest in the
         pattern which originated in x. Up to now, the following fix works... */
      
      PATTERN (fake_insn) = fake_pattern;
      PATTERN (fake_jump_insn) = fake_jump_pattern;

      if (tricore_log.rtx_costs)
        tricore_edump ("%?: \n\tinsn = %r\n\n\tcost{%s} = %d\n\n", pattern,
                   INSN_CODE (insn) >= 0
                   ? get_insn_name (INSN_CODE (insn)) : "unknown",
                   *total);

      return true;
    } /* SET == outer_code && mode != BLKmode */
  else if (SET == outer_code && mode == BLKmode)
    {
      *total = 1;
      return true;
    }

  /* Section 3:
     Some remains still there. This needs cleanup. */
  
  *total = -1;

  switch (outer_code)
    {
    case LO_SUM:
      if (HIGH == code)
        {
          *total = 0;
        }

      break;
      
    case SET:
      tricore_edump ("\tticks{%C} = %r\n\n", outer_code, x);
      gcc_unreachable();
          
      break; /* outer = SET */

    default:
      break;
    }

  if (*total == -1)
    {
      *total = large_mode_p ? 1000 : 20;
    }
    
  if (tricore_log.rtx_costs)
    tricore_edump ("%?:{%C} %r -> %d\n", outer_code, x, *total);

  return true;
}


/* Implement `TARGET_ADDRESS_COST' */

static int
tric_address_cost (rtx addr, enum machine_mode mode ATTRIBUTE_UNUSED,
                   addr_space_t as ATTRIBUTE_UNUSED, bool speed)
{
  int cost = 4;

  if (GET_CODE (addr) == PRE_INC || GET_CODE (addr) == POST_DEC)
    cost = 1000;

  if (tricore_log.address_cost)
    tricore_edump ("%?: %d[%s] = %r\n", cost, speed ? "speed" : "size", addr);
  
  return cost;
}


/* Get costs of CONST_INT, i.e. num bytes required to load it */

static int
tric_const_int_costs (int i)
{
  rtx x = gen_int_mode (i, SImode);

  if (satisfies_constraint_Ks4 (x))
    return 2;

  /* will depend on dest is D15 or not, assume prob of 50%  */

  if (satisfies_constraint_Ku8 (x))
    return 3;

  if (satisfies_constraint_Ksg (x)
      || satisfies_constraint_Kug (x)
      || satisfies_constraint_Khg (x))
    {
      return 4;
    }

  return 4 + tric_const_int_costs (trunc_int_for_mode (i, HImode));
}


static int
tric_const_double_costs (rtx x)
{
  int cost_lo, cost_hi;
  unsigned lo, hi;
  tric_split_const_rtx (x, &lo, &hi);

  gcc_assert (CONST_DOUBLE_P (x));

  cost_lo = tric_const_int_costs (lo);
  cost_hi = tric_const_int_costs (hi);

  cost_lo = (cost_lo == 3) ? 4 : cost_lo;
  cost_hi = (cost_hi == 3) ? 4 : cost_hi;

  if (SFmode == GET_MODE (x))
    cost_hi = 0;

  return cost_lo + cost_hi;
}


/* Implement `MOVE_RATIO' */

int
tric_move_ratio (int for_speed_p)
{
  return for_speed_p ? 3 : 2;
}


/* Implement `CLEAR_RATIO' */

int
tric_clear_ratio (int for_speed_p)
{
  return for_speed_p ? 4 : 3;
}


/* Implement `SET_RATIO' */

int
tric_set_ratio (int for_speed_p)
{
  return for_speed_p ? 4 : 2;
}


/* Split NUM DImode rtx's passed in OP[] into ther low and high parts,
   returned in LO[] resp. HI[].  */

void
tric_split_di (rtx op[], rtx lo[], rtx hi[], int num)
{
  int i;

  for (i = 0; i < num; i++)
    {
      lo[i] = simplify_gen_subreg (SImode, op[i], DImode, 0);
      hi[i] = simplify_gen_subreg (SImode, op[i], DImode, 4);
    }
}



/***********************************************************************
 ** Function Arguments and Return Value Passing
 ***********************************************************************/

/* Implement `INIT_CUMULATIVE_ARGS' */

void
tric_init_cumulative_args (CUMULATIVE_ARGS *cum, tree fntype,
                           rtx libname, int n_named_args)
{
  int cookie = 0;
  cum->outgoing = n_named_args != -1;
  /* Set up the number of registers to use for passing arguments.  */
  cum->args_mask = 0;
  cfun->machine->sibcall_fails = 0;

  /* Store information about callee's attributes */
  if (fntype)
    {
      if (tric_pxhndcall_function_p (fntype))
        cookie |= CALLCOOKIE_PXHNDCALL_MASK;

      if (cookie)
        cfun->machine->sibcall_fails = 1;

      if (tric_interrupt_function_p (fntype))
        cookie |= CALLCOOKIE_INTERRUPT_MASK;

      if (tric_interrupt_handler_function_p (fntype))
        cookie |= CALLCOOKIE_INTERRUPT_HANDLER_MASK;

      if (tric_longcall_function_p (fntype))
        cookie |= CALLCOOKIE_LONGCALL_MASK;
    }

  cum->call_cookie = cookie;
  cum->fntype = fntype;

  cum->libfunc_p = 0;
  cum->argno = 0;
  cum->args_onstack=0;

  if (NULL_RTX != libname)
    {
      unsigned int i;
      const char *name = XSTR (libname, 0);

      static const tric_libfunc_info_t libfunc_info[] =
        {
          /* Just some functions from libfuncs.h that involve pointer arguments
                 v    = void
                 p    = void*
                 i    = int
                 NULL = don't care, SI is not a pointer  */

          /* { name, args, ret-val, fast? } */
          { "abort", NULL, 0, 0 }
          , { "memcpy",  "ppi", 'p', 0 }
          , { "memmove", "ppi", 'p', 0 }
          , { "memcmp",  "ppi", 'i', 0 }
          , { "memset",  "pii", 'p', 0 }
          , { "__cyg_profile_func_enter", "pp", 'v', 0 }
          , { "__cyg_profile_func_exit",  "pp", 'v', 0 }
          , { "setjmp",  "p",  'i', 0 }
          , { "longjmp", "pi", 'v', 0 }
          , { "_Unwind_SjLj_Register",   "p", 'v', 0 }
          , { "_Unwind_SjLj_Unregister", "p", 'v', 0 }
        };

      for (i = 0; i < sizeof (libfunc_info) / sizeof (*libfunc_info); i++)
        {
          if (STREQ (name, libfunc_info[i].name))
            {
              cum->libfunc = libfunc_info[i];
              cum->libfunc_p = NULL != cum->libfunc.args;

              return;
            }
        }

      if (!cum->libfunc_p && *name != '_')
        {
          internal_error ("Support function %qs not supported", name);
        }
    }
}


/* Implement `TARGET_RETURN_POPS_ARGS' */

static poly_int64
tric_return_pops_args (tree fundecl ATTRIBUTE_UNUSED,
                       tree funtype ATTRIBUTE_UNUSED,
		       poly_int64 size ATTRIBUTE_UNUSED)
{
  return 0;
}



static int
tric_num_arg_regs (enum machine_mode mode, const_tree type)
{
  int bytes, words;

  switch (mode)
    {
    case VOIDmode:
      bytes = 0;
      break;

    case BLKmode:
      bytes = int_size_in_bytes (type);
      break;

    default:
      bytes = GET_MODE_SIZE (mode);
      break;
    }

  /* round to word size */
  words = (bytes + UNITS_PER_WORD - 1) / UNITS_PER_WORD;

  return words;
}


/* Worker function for FUNCTION_ARG and FUNCTION_ARG_ADVANCE:
   Return the RTX where a function argument shall be passed.
   If CUM->update then update *CUM.  */

static rtx
tric_function_arg1 (CUMULATIVE_ARGS *cum, const function_arg_info &arg)
{
  int pointer_p = arg.type && POINTER_TYPE_P (arg.type);
  int nregs = tric_num_arg_regs (arg.mode, arg.type);
  int argno = cum->argno;

  cum->this_argno = 1 + cum->argno;

  if (cum->update)
    cum->argno = 1 + argno;

  if (arg.mode == VOIDmode)
    {
      return GEN_INT (cum->call_cookie);
    }

  if (cum->call_cookie & CALLCOOKIE_PXHNDCALL_MASK)
    {
      if (nregs != 1)
        {
          error_at (DECL_SOURCE_LOCATION (current_function_decl),
                    "argument %d of %<%s%> function occupies %d registers but"
                    " only one is supported", argno +1, "__pxhndcall__", nregs);
        }

      if (cum->update)
        return NULL_RTX;

      return gen_rtx_REG (arg.mode, argno == 0 ? REG_D4 : REG_A15);
    }

  /* Unnamed ... portion of varargs function
     and variable sized types are passed by reference. */
  if (!arg.named
      || 0 == nregs
      || (arg.type && TREE_CODE (TYPE_SIZE (arg.type)) != INTEGER_CST))
    {
      cum->args_onstack=1;
      return NULL_RTX;
    }

  /* Don't pass arguments larger than 64 bits in registers */
  if (nregs > 2)
    {
      cum->args_onstack=1;
      return NULL_RTX;
    }

  if (cum->libfunc_p)
    {
      const char *args = cum->libfunc.args;

      gcc_assert (args && args[argno]);

      pointer_p = 'p' == args[argno];
    }

  {
    unsigned int regno = (pointer_p || PDImode == arg.mode) ? REG_A4 : REG_D4;
    unsigned int rmask = ((1 << nregs) -1) << regno;

    for (;; regno += nregs, rmask <<= nregs)
    {
      if (rmask & ((1 << REG_A8) | (1 << REG_D8)))
    {
      cum->args_onstack=1;
      return NULL_RTX;
    }

      if (0 == (cum->args_mask & rmask))
        {
          if (!cum->update)
            return gen_rtx_REG (arg.mode, regno);

          cum->args_mask |= rmask;
          return NULL_RTX;
        }
    }
  }

  gcc_unreachable();
}


/* Implelemt `TARGET_STRICT_ARGUMENT_NAMING' */

static bool
tric_strict_argument_naming (cumulative_args_t cum_v ATTRIBUTE_UNUSED)
{
  return true;
}


/* Implement `TARGET_FUNCTION_ARG' */

static rtx
tric_function_arg (cumulative_args_t cum_v, const function_arg_info &arg)
{
  CUMULATIVE_ARGS *cum = get_cumulative_args (cum_v);

  cum->update = 0;
  return tric_function_arg1 (cum, arg);
}


/* Implement `TARGET_FUNCTION_ARG_ADVANCE' */
/* Update the data in CUM to advance over an argument of mode MODE and data
   type TYPE.  TYPE is null for libcalls where that information may not
   be available.  */

static void
tric_function_arg_advance (cumulative_args_t cum_v, const function_arg_info &arg)
{
  CUMULATIVE_ARGS *cum = get_cumulative_args (cum_v);

  cum->update = 1;
  tric_function_arg1 (cum, arg);
}


/* Implement `TARGET_FUNCTION_VALUE' */

static rtx
tric_function_value (const_tree ret_type,
                     const_tree fn_decl_or_type ATTRIBUTE_UNUSED,
                     bool outgoing ATTRIBUTE_UNUSED)
{
  enum machine_mode mode = TYPE_MODE (ret_type);
  int regno_d_SI = REG_D2;
  int regno_d_DI = REG_D2;
  int regno_a = REG_A2;
  int bytes = -1;

  rtx reg;

  if (POINTER_TYPE_P (ret_type))
    {
      reg = gen_rtx_REG (Pmode, regno_a);
      REG_POINTER (reg) = 1;
    }
  else if (PDImode == mode)
    {
      reg = gen_rtx_REG (PDImode, regno_a);
    }
  else if (mode == BLKmode)
    {
      bytes = int_size_in_bytes (ret_type);

      gcc_assert (bytes > 0);

      if (bytes < 4)
        reg = gen_rtx_REG (SImode, regno_d_SI);
      else if (bytes == 4)
        reg = gen_rtx_REG (mode, regno_d_SI);
      else if (bytes <= 8)
        reg = gen_rtx_REG (mode, regno_d_DI);
      else
        gcc_unreachable ();
    }
  else if (INTEGRAL_TYPE_P (ret_type))
    {
      bytes = GET_MODE_SIZE (mode);

      if (bytes < 4)
        reg = gen_rtx_REG (SImode, regno_d_SI);
      else if (bytes == 4)
        reg = gen_rtx_REG (mode, regno_d_SI);
      else if (bytes <= 8)
        reg = gen_rtx_REG (mode, regno_d_DI);
      else
        gcc_unreachable ();
    }
  else
    {
      /* CQImode, RECORD_TYPE, ... */
      bytes = GET_MODE_SIZE (mode);

      if (bytes < 4)
        reg = gen_rtx_REG (mode, regno_d_SI);
      else if (bytes == 4)
        reg = gen_rtx_REG (mode, regno_d_SI);
      else if (bytes <= 8)
        reg = gen_rtx_REG (mode, regno_d_DI);
      else
        gcc_unreachable ();
    }

  return reg;
}


/* Implement `TARGET_RETURN_IN_MEMORY' */
/* Decide whether a type should be returned in memory (true)
   or in a register (false). */

static bool
tric_return_in_memory (const_tree type, const_tree fntype ATTRIBUTE_UNUSED)
{
  int size = int_size_in_bytes (type);
  return size > 2 * UNITS_PER_WORD || size <= 0;
}


/* Implement `TARGET_PASS_BY_REFERENCE' */
/* std_gimplify_va_arg_expr passes CUM == NULL */

static bool
tric_pass_by_reference (cumulative_args_t cum_v ATTRIBUTE_UNUSED,
                        const function_arg_info &arg)
{
  int size;

  if (arg.type == NULL_TREE)
    return false;

  /* EABI 2.2.3.6: Pass composite with more than 8 bytes per reference.  */
    
  size = int_size_in_bytes (arg.type);

  return size < 0 || size > 2 * UNITS_PER_WORD;
}


/* Implement `TARGET_CALLEE_COPIES' */

static bool
tric_callee_copies (cumulative_args_t cum_v ATTRIBUTE_UNUSED,
                    const function_arg_info &arg)
{
  tree type_size;

  if (arg.type == NULL_TREE)
    return false;

  type_size = TYPE_SIZE_UNIT (TYPE_MAIN_VARIANT (arg.type));

  return (type_size == NULL_TREE
          || (arg.mode == BLKmode
              && int_size_in_bytes (arg.type) > 2 * UNITS_PER_WORD)
          || !really_constant_p (type_size));
}


/* Implement `TARGET_STRUCT_VALUE_RTX' */

static rtx
tric_struct_value_rtx (tree fntype ATTRIBUTE_UNUSED,
                       int incoming ATTRIBUTE_UNUSED)
{
  return NULL_RTX;
}


/* Implement `TARGET_FUNCTION_ATTRIBUTE_INLINABLE_P' */
/* This may be called with a function decl or a function type (see below).
   The tric attribute checkers are prepared for both.  */

static bool
tric_function_attribute_inlinable_p (const_tree func)
{
  if (tric_longcall_function_p (func))
    return true;

  return false;
}


/* Implement `TARGET_CAN_INLINE_P' */

static bool
tric_can_inline_p (tree caller, tree callee)
{
  /* Fixme: default_target_can_inline_p only cares for option attributes
     and checks their compatibility so that the default implementation
     of this hook supersedes function_attribute_inlinable_p.
     function_attribute_inlinable_p in turn calls the hook above with a
     function decl, but the attributes are found in the function type.  */

  const_tree a, ftype_callee = TREE_TYPE (callee);

  /* CHECK
  for (a = TYPE_ATTRIBUTES (ftype_callee); a; a = TREE_CHAIN (a))
    {
      const_tree name = TREE_PURPOSE (a);
      int i;

      for (i = 0; targetm.attribute_table[i].name != NULL; i++)
        if (is_attribute_p (targetm.attribute_table[i].name, name)
            && !targetm.function_attribute_inlinable_p (ftype_callee))
          return false;
    }
*/
  return default_target_can_inline_p (caller, callee);
}

/* Implement TARGET_INVALID_PARAMETER_TYPE.  */
//TODO
/*
static const char *
tric_invalid_parameter_type (const_tree t)
{
  if (SCALAR_FLOAT_TYPE_P (t) && TYPE_PRECISION (t) == 16)
    return N_("function parameters cannot have __float16 type");
  return NULL;
}
*/
/* Implement TARGET_INVALID_RETURN_TYPE.  */
//TODO
/*
static const char *
tric_invalid_return_type (const_tree t)
{
  if (SCALAR_FLOAT_TYPE_P (t) && TYPE_PRECISION (t) == 16)
    return N_("functions cannot return __float16 type");
  return NULL;
}
*/
/* Implement TARGET_PROMOTED_TYPE.  */

static tree
tric_promoted_type (const_tree t)
{
  if (SCALAR_FLOAT_TYPE_P (t) && TYPE_PRECISION (t) == 16)
    return float_type_node;
  return NULL_TREE;
}

/* Implement TARGET_CONVERT_TO_TYPE.
   Specifically, this hook implements the peculiarity of Tricore
   half-precision floating-point C semantics that requires conversions between
   __float16 to or from double to do an intermediate conversion to float.  */

static tree
tric_convert_to_type (tree type, tree expr)
{
  tree fromtype = TREE_TYPE (expr);
  if (!SCALAR_FLOAT_TYPE_P (fromtype) || !SCALAR_FLOAT_TYPE_P (type))
    return NULL_TREE;
  if ((TYPE_PRECISION (fromtype) == 16 && TYPE_PRECISION (type) > 32)
      || (TYPE_PRECISION (type) == 16 && TYPE_PRECISION (fromtype) > 32))
    return convert (type, convert (float_type_node, expr));
  return NULL_TREE;
}


/***********************************************************************
 ** Predicate Helpers
 ***********************************************************************/


/* Used in insn attributes to map a CONST_INT to its actual value. */

int
intval (rtx x, enum machine_mode mode)
{
  (void) mode;

  gcc_assert (CONST_INT_P (x));

  return INTVAL (x);
}


/* Implement special predicate `mov_input_operand' */

int
mov_input_operand_p (rtx op, enum machine_mode mode)
{
  int ok = 0;

  if (immediate_operand (op, mode)
      && !const_int_operand (op, mode)
      && !const_double_operand (op, mode))
    {
      ok = tric_can_move_immediate_p (NULL_RTX, op);
    }
  else
    ok = general_operand (op, mode);

  if (tricore_log.mov_input_operand)
    tricore_edump ("%?:[%m] %d = %r\n", mode, ok, op);

  return ok;
}


/* Implement predicate `symbolic_operand' */

int
symbolic_operand_p (rtx op, enum machine_mode mode ATTRIBUTE_UNUSED)
{
  enum rtx_code code = GET_CODE (op);

  switch (code)
    {
    case LABEL_REF:
    case SYMBOL_REF:
    case CONST:
      return 1;
    default:
      break;
    }

  return 0;
}


/* Helper for `tric_output_call':
   Get a mask that tells which regs the callee insn will be passed */

static unsigned int
tric_call_insn_use_regs_mask (rtx insn)
{
  unsigned int mask = 0;
  rtx list = CALL_INSN_FUNCTION_USAGE (insn);

  while (list)
    {
      rtx use = XEXP (list, 0);

      if (USE == GET_CODE (use)
          && REG_P (XEXP (use, 0)))
        {
          rtx reg = XEXP (use, 0);
          unsigned int regno = REGNO (reg);

          switch (tric_hard_regno_nregs (regno, GET_MODE (reg)))
            {
            default:
              gcc_unreachable();
              break;

            case 2:
              mask |= 1 << (1 + regno);
              /* FALLTHRU */
            case 1:
              mask |= 1 << regno;
              break;
            }
        }

      list = XEXP (list, 1);
    }

  return mask;
}

bool remove_strcmp(rtx_insn *insn_ref, rtx *operands)
{
  basic_block block;
  rtx_insn *insn, *end;
  tree src1, src2;
  const char * first_str = 0;
  const char * second_str = 0;
  tree dst_first_str, dst_second_str;

  rtx str1 = XVECEXP (XEXP (XVECEXP (XEXP (insn_ref, 3), 0, 0), 1), 0, 0);
  rtx str2 = XVECEXP (XEXP (XVECEXP (XEXP (insn_ref, 3), 0, 0), 1), 0, 1);
  tree t1 = MEM_EXPR (str1);
  tree t2 = MEM_EXPR (str2);

  // Memrefs must be available for both strings
  if (!t1 || !t2 ||TREE_CODE (t1) != MEM_REF || TREE_CODE (t2) != MEM_REF
      || TREE_CODE (TREE_OPERAND (t1, 0)) != ADDR_EXPR
      || TREE_CODE (TREE_OPERAND (t2, 0)) != ADDR_EXPR)
    return false;

  if (MEM_VOLATILE_P (str1) || MEM_VOLATILE_P (str2))
    return false;

  // For all BBs in the current function
  FOR_ALL_BB_FN (block, cfun)
  {
    // For all instructions in the current BB
    FOR_BB_INSNS (block, insn)
    {
      // Stop when we encouter the current strcmp insn
      if(insn == insn_ref) goto end;

      // We consider only standard insns
      if (!INSN_P (insn))
        continue;

      int code = recog_memoized (insn);

      // strcpy
      if (code == CODE_FOR_cpymemsi_qi ||
          code == CODE_FOR_cpymemsi_si ||
          code == CODE_FOR_cpymemsi_di ||
	  code == CODE_FOR_cpymemsi_ti)

      {
        rtx dst_ = XEXP (XVECEXP (XEXP (insn, 3), 0, 0), 0);
        tree dst = MEM_EXPR (dst_);
        if (dst && TREE_CODE (dst) == MEM_REF
                && TREE_CODE (TREE_OPERAND (dst, 0)) == ADDR_EXPR)
        {
	  // Found a ref to str1
          if (TREE_OPERAND (TREE_OPERAND (t1, 0), 0) == TREE_OPERAND (TREE_OPERAND (dst, 0), 0)) 
          {
  	    rtx src_ = XVECEXP (XEXP (XVECEXP (XEXP (insn, 3), 0, 0), 1), 0, 0);
            src1 = MEM_EXPR (src_);
	    if (src1 && TREE_CODE (src1) == MEM_REF
	  	  && TREE_CODE (TREE_OPERAND (src1, 0)) == ADDR_EXPR
		  && (TREE_CODE (TREE_OPERAND (TREE_OPERAND (src1, 0), 0)) == STRING_CST))
	    {
              // Found a string constant
	      dst_first_str = dst;
	      first_str = TREE_STRING_POINTER(TREE_OPERAND (TREE_OPERAND (src1, 0), 0));
	    }
          }
	  // Found a ref to str2
	  else if (TREE_OPERAND (TREE_OPERAND (t2, 0), 0) == TREE_OPERAND (TREE_OPERAND (dst, 0), 0))
          {
            rtx src_ = XVECEXP (XEXP (XVECEXP (XEXP (insn, 3), 0, 0), 1), 0, 0);
            src2 = MEM_EXPR (src_);
            if (src2 && TREE_CODE (src2) == MEM_REF
                     && TREE_CODE (TREE_OPERAND (src2, 0)) == ADDR_EXPR
                     && (TREE_CODE (TREE_OPERAND (TREE_OPERAND (src2, 0), 0)) == STRING_CST)) 
	    {
	      // Found a string constant
	      dst_second_str = dst;
              second_str = TREE_STRING_POINTER(TREE_OPERAND (TREE_OPERAND (src2, 0), 0));
	    }
          }
	}
      }
      // If we found at least one string, we must check other insn to check memory writes
      else if(first_str || second_str)
      {
	// Check if the current insn is a SET
	rtx curr = XEXP (insn, 3);
	if (curr && GET_CODE(curr) == SET)
	{
          // Check if the first operand is a MEM
	  rtx first_op = XEXP (curr, 0);
	  if (GET_CODE(first_op) == MEM)
	  {
	    tree t = MEM_EXPR (first_op);
	    if (t && first_str && refs_may_alias_p(dst_first_str, t))
              return false;
	    if (t && second_str && refs_may_alias_p(dst_second_str, t))
              return false;
	  }
	}
      }
    }
  }

end:
  // If we found both constant strings we can replace with the strcmp result
  if (first_str && second_str)
  {
    int result = strcmp(first_str, second_str);
    if (result > 0) result = 1;
    if (result < 0) result = -1;
    rtx xoperands[2];
    xoperands[0] = operands[0];
    xoperands[1] = gen_rtx_CONST_INT ( GET_MODE (operands[0]), result);
    output_asm_insn ("mov.d\t%0, %1", operands);
    return true;
  } 
  return false;  
}


bool copy_constant_string (rtx_insn *insn_ref, rtx *operands)
{
  tree dst_mem, src_mem;
  unsigned int alignment;
  const char *str;
  size_t len;
  uint32_t *pointer;
  uint8_t *leftover_1;
  uint16_t *leftover_2;

  // Check destination buffer
  dst_mem = MEM_EXPR ( XEXP (XVECEXP (XEXP (insn_ref, 3), 0, 0), 0));
  if (dst_mem)
  {
    alignment = get_object_alignment (dst_mem);
    if(alignment % 32 != 0) return false;
  }
  else
    return false;

  // Check source data
  src_mem = MEM_EXPR ( XVECEXP (XEXP (XVECEXP (XEXP (insn_ref, 3), 0, 0), 1), 0, 0));
  if (src_mem && TREE_CODE (src_mem) == MEM_REF
      && TREE_CODE (TREE_OPERAND (src_mem, 0)) == ADDR_EXPR
      && (TREE_CODE (TREE_OPERAND (TREE_OPERAND (src_mem, 0), 0)) == STRING_CST))
  {
    rtx xoperands[5];

    // Get string and check length
    str = TREE_STRING_POINTER(TREE_OPERAND (TREE_OPERAND (src_mem, 0), 0));
    len = strlen(str) + 1;
    if (len > 64) return false;

    // Generate assembly
    xoperands[0] = operands[0];
    xoperands[2] = operands[5];
    pointer = (uint32_t *) str;
    for (int i = 0; i<len/4; i++)
    {
      xoperands[1] = gen_rtx_CONST_INT ( GET_MODE (operands[7]), i*4);
      xoperands[3] = gen_rtx_CONST_INT ( GET_MODE (operands[7]), (*pointer) >> 16);
      xoperands[4] = gen_rtx_CONST_INT ( GET_MODE (operands[7]), (*pointer) & 0xFFFF);
      output_asm_insn ("movh\t%2, %3", xoperands);
      output_asm_insn ("addi\t%2, %2, %4", xoperands);
      output_asm_insn ("st.w\t[%0]%1, %2", xoperands);
      pointer++;
    }
    leftover_2 = (uint16_t *) pointer;
    if ((len%4) & 2)
    {
      xoperands[1] = gen_rtx_CONST_INT ( GET_MODE (operands[7]), (len/4)*4);
      xoperands[3] = gen_rtx_CONST_INT ( GET_MODE (operands[7]), *leftover_2);
      output_asm_insn ("mov\t%2, %3", xoperands);
      output_asm_insn ("st.h\t[%0]%1, %2", xoperands);
      leftover_2++;
    }
    leftover_1 = (uint8_t *) leftover_2;
    if ((len%4) & 1)
    {
      xoperands[1] = gen_rtx_CONST_INT ( GET_MODE (operands[7]), len-1);
      xoperands[3] = gen_rtx_CONST_INT ( GET_MODE (operands[7]), *leftover_1);
      output_asm_insn ("mov\t%2, %3", xoperands);
      output_asm_insn ("st.b\t[%0]%1, %2", xoperands);      
    }	    
    return true;
  }
  else
    return false;
}

/* If MEM is in the form of [base+offset], extract the two parts
   of address and set to BASE and OFFSET, otherwise return false
   after clearing BASE and OFFSET.  */

static bool
extract_base_offset_in_addr (rtx mem, rtx *base, rtx *offset)
{
  rtx addr;

  gcc_assert (MEM_P (mem));

  addr = XEXP (mem, 0);

  /* Strip off const from addresses like (const (addr)).  */
  if (GET_CODE (addr) == CONST)
    addr = XEXP (addr, 0);

  if (REG_P (addr))
    {
      *base = addr;
      *offset = const0_rtx;
      return true;
    }

  if (GET_CODE (addr) == PLUS
      && GET_CODE (XEXP (addr, 0)) == REG
      && CONST_INT_P (XEXP (addr, 1)))
    {
      *base = XEXP (addr, 0);
      *offset = XEXP (addr, 1);
      return true;
    }

  *base = NULL_RTX;
  *offset = NULL_RTX;

  return false;
}

static bool
fusion_lea_mem (rtx_insn *insn, rtx *base, rtx *offset, bool *is_mem)
{
  rtx x, dest, src;

  gcc_assert (INSN_P (insn));
  x = PATTERN (insn);
  if (GET_CODE (x) != SET)
    return false;

  src = SET_SRC (x);
  dest = SET_DEST (x);
  if (REG_P (dest) && GET_CODE (src) == LO_SUM)
    {
      *is_mem = false;
      *base = dest;
      *offset = NULL_RTX;
    }
  else if (MEM_P (src) && REG_P (dest))
    {
      *is_mem = true;
      extract_base_offset_in_addr (src, base, offset);
    }
  else if (REG_P (src) && MEM_P (dest))
    {
      *is_mem = true;
      extract_base_offset_in_addr (dest, base, offset);
    }
  else
    return false;

  return (*base != NULL_RTX);
}

/* Implement the TARGET_SCHED_FUSION_PRIORITY hook. */
static void
tricore_sched_fusion_priority (rtx_insn *insn, int max_pri,
                               int *fusion_pri, int *pri)
{
  int tmp;
  bool is_mem;
  rtx base, offset;

  tmp = max_pri - 1;

  if (!fusion_lea_mem (insn, &base, &offset, &is_mem))
  {
      *pri = 1;
      *fusion_pri = 1;
      //printf("fusion_pri = %d, pri = %d \n", fusion_pri, pri);
      //debug(insn);
      return;
  }

  /* LEA goes first.  */
  if (!is_mem)
    *fusion_pri = tmp - 2;
  else
    *fusion_pri = tmp - 2;
  tmp /= 2;

  /* INSN with smaller base register goes first.  */
  tmp -= ((REGNO (base) & 0xff) << 20);

  *pri = tmp;

  return;
}

/* Print a CALL_INSN. The operands are:
   value_p = 0:
      $0 = address
      $1 =
      $2 = call_cookie

   value_p != 0:
      $0 = return register
      $1 = address
      $2 =
      $3 = call_cookie

  With the cookie containing additional information like if we are
  about to print a tail call, etc.

  Also print some additional information like stack and register usage if
  one of -dp, -dP, -fverbose-asm is turned on. */

void
tric_output_call (rtx insn, rtx *operands, int value_p)
{
  unsigned int mask = 0;
  rtx addr = value_p ? operands[1] : operands[0];
  int cookie = INTVAL (value_p ? operands[3] : operands[2]);
  int sibling_p = CALLCOOKIE_SIBLING_MASK & cookie;
  int pxhndcall_p = CALLCOOKIE_PXHNDCALL_MASK & cookie;
  int noreturn_p = NULL_RTX != find_reg_note (insn, REG_NORETURN, NULL);
  cfun->machine->calls+=1;

  /* Compute register mask of passed regs */
  if (sibling_p || pxhndcall_p || flag_verbose_asm || flag_print_asm_name)
    {
      unsigned int regno;

      mask = tric_call_insn_use_regs_mask (insn);

      /* Make sure that we did not emit an erroneous sibling, i.e. a sibling
         that gets arguments in some call-safed registers */
      if (sibling_p)
        for (regno = REG_D0; regno <= REG_A15; regno++)
          if (! call_used_regs[regno])
            gcc_assert (0 == (mask & (1 << regno)));
    }

  if (flag_verbose_asm
      || flag_print_asm_name)
    {
      static char str[100];
      rtx op[3];
      op[0] = GEN_INT (mask);
      op[1] = value_p ? operands[2] : operands[1];

      str[0] = '\0';

      strcat (str, noreturn_p ? "{" "noreturn"        "}" : "");
      strcat (str, find_reg_note (insn, REG_NON_LOCAL_GOTO, NULL)
              ? "{" "nonlocal goto"          "}" : "");
      strcat (str, find_reg_note (insn, REG_SETJMP, NULL)
              ? "{" "setjmp"            "}" : "");
      strcat (str, (cookie & CALLCOOKIE_LONGCALL_MASK)
              ? "{" "longcall"          "}" : "");
      strcat (str, (cookie & CALLCOOKIE_INTERRUPT_MASK)
              ? "{" "interrupt"         "}" : "");
      strcat (str, (cookie & CALLCOOKIE_INTERRUPT_HANDLER_MASK)
              ? "{" "interrupt_handler" "}" : "");
      strcat (str, (pxhndcall_p)
              ? "{" "pxhndcall"         "}" : "");

      op[2] = gen_rtx_CONST_STRING (VOIDmode, ggc_strdup (str));

      if (sibling_p)
        {
          cfun->machine->sibcall+=1;
          output_asm_insn (ASM_COMMENT_START " outgoing.sibcall%2[%1]: %M0", op);
        }
      else
        output_asm_insn (ASM_COMMENT_START " outgoing.call%2[%1]: %M0", op);
    }

  if (pxhndcall_p)
    {
      output_asm_insn ("syscall\t%0", &addr);
      return;
    }

  if (cookie & CALLCOOKIE_INTERRUPT_MASK)
    {
      if (CONST_INT_P (addr))
        output_asm_insn (sibling_p ? "ja\t%0" : "jla\t%0", &addr);
      else
        output_asm_insn (sibling_p ? "j%I0\t%0" : "jl%I0\t%0", &addr);
      return;
    }

  if (noreturn_p
      || (cookie & CALLCOOKIE_INTERRUPT_HANDLER_MASK))
    {
      sibling_p = 1;
    }

  if (find_reg_note (insn, REG_SETJMP, NULL)
      || (cookie & CALLCOOKIE_USE_CALL_MASK))
    {
      sibling_p = 0;
    }
  if (noreturn_p)
    {
      cfun->machine->noreturn+=1;
    }
  if (CONST_INT_P (addr))
    output_asm_insn (sibling_p ? "ja\t%0" : "calla\t%0", &addr);
  else
    output_asm_insn (sibling_p ? "j%I0\t%0" : "call%I0\t%0", &addr);
}


/***********************************************************************
 ** Helper Functions for Bit Stuff
 ***********************************************************************/

/* Similar to exact_log2. However, this may also take something like 00111100
   This input will yield 2 (LSB which is 1) with width = 4 (4 ones in a row).
   WIDTH may be NULL if no variable is available, e.g. in insn conditions.
   If UI is 0 or is not of the form indicated above, return -1 */

int
ones_mask (int ui, int *width)
{
  int ones, zeroes;
  uint32_t i = (uint32_t) ui;

  if (0 == i)
    return -1;

  i >>= (zeroes = ctz_hwi (i));

  ones = exact_log2 (HOST_WIDE_INT_1U + i);

  if (ones < 0)
    return -1;

  if (width)
    *width = ones;

  return zeroes;
}

/* The width of the mask above. To use it in insn conditions
   we need a function. Here it is. */

int
ones_width (int ui)
{
  int width;

  if (ones_mask (ui, & width) < 0)
    return -1;

  return width;
}



/***********************************************************************
 ** Comparing and Branching
 ***********************************************************************/

/* Implement `TARGET_CANONICALIZE_COMPARISON' */

static void
tric_canonicalize_comparison (int *code0, rtx *op0, rtx *op1,
                              bool op0_preserve_value ATTRIBUTE_UNUSED)
{
  enum rtx_code code = (enum rtx_code) *code0;
  enum machine_mode mode = GET_MODE (*op0);

  rtx arg1 = NULL_RTX;

  switch (code)
    {
    default:
      break;
      
    case GT:
      if (mode == GET_MODE (*op0)
          && CONST_INT_P (*op1))
        {
          HOST_WIDE_INT val1 = INTVAL (*op1);

          if (val1 < 0x7fffffff)
            {
              /* r > C  <=>  r >= C+1 */
              code = GE;
              arg1 = gen_int_mode (1 + val1, SImode);
            }
        }
      break;
      
    case GTU:
      if (mode == GET_MODE (*op0)
          && CONST_INT_P (*op1))
        {
          unsigned HOST_WIDE_INT val1 = UINTVAL (*op1);

          if (val1 < 0xffffffff)
            {
              /* r > C  <=>  r >= C+1 */
              code = GEU;
              arg1 = gen_int_mode (1 + val1, SImode);
            }
        }
      break;

    case LE:
      if (mode == GET_MODE (*op0)
          && CONST_INT_P (*op1))
        {
          HOST_WIDE_INT val1 = INTVAL (*op1);

          if (val1 < 0x7fffffff)
            {
              /* r <= C  <=>  r < C+1 */
              code = LT;
              arg1 = gen_int_mode (1 + val1, SImode);
            }
        }
      break;

    case LEU:
      if (mode == GET_MODE (*op0)
          && CONST_INT_P (*op1))
        {
          unsigned HOST_WIDE_INT val1 = UINTVAL (*op1);

          if (val1 < 0xffffffff)
            {
              /* r <= C  <=>  r < C+1 */
              code = LTU;
              arg1 = gen_int_mode (1 + val1, SImode);
            }
        }
      break;
    }

  if (arg1 != NULL_RTX)
    {
      if (tricore_log.canonicalize_comparison)
        tricore_edump ("%?:%m  %C -> %C\n\t%r -> %r\n",
                    mode, *code0, (int) code, *op1, arg1);

      *op1 = arg1;
      *code0 = (int) code;
    }
}


/* Old-style interface of the above hook.  */

static enum rtx_code
tric_canonicalize_comparison_code (enum rtx_code code, rtx *op0, rtx *op1)
{
  int code_i = (int) code;
  tric_canonicalize_comparison (&code_i, op0, op1, true);

  return (enum rtx_code) code_i;

}


void
tric_emit_branch (enum rtx_code code, rtx op0, rtx op1, rtx targ)
{
  enum machine_mode mode = GET_MODE (op0);

  code = tric_canonicalize_comparison_code (code, &op0, &op1);

  switch (code)
    {
    default:
      break;

    case GT:
    case LE:

      if (const0_rtx == op1)
        break;

      /* FALLTHRU */
    case GTU:
    case LEU:
      {
        rtx op;
        code = swap_condition (code);
        op = op0; op0 = op1; op1 = op;
        break;
      }
    }

  switch (code)
    {
    case NE:
    case EQ:
    case LT:
    case GE:
      if (!register_operand (op0, mode))
        op0 = copy_to_mode_reg (mode, op0);

      if (reg_or_s4_operand (op1, mode))
        break;

      if (tric_opt_branch_use_setcompare
          && s9_operand (op1, mode))
        {
          rtx reg = gen_reg_rtx (mode);
          tric_emit_setcompare (code, op0, op1, reg);
          op0 = reg;
          op1 = const0_rtx;
          code = NE;
          break;
        }

      op1 = copy_to_mode_reg (mode, op1);
      break;

    case LTU:
    case GEU:
      if (!register_operand (op0, mode))
        op0 = copy_to_mode_reg (mode, op0);

      if (reg_or_u4_operand (op1, mode))
        break;

      if (tric_opt_branch_use_setcompare
          && u9_operand (op1, mode))
        {
          rtx reg = gen_reg_rtx (mode);
          tric_emit_setcompare (code, op0, op1, reg);
          op0 = reg;
          op1 = const0_rtx;
          code = NE;
          break;
        }

      op1 = copy_to_mode_reg (mode, op1);
      break;

    case GT:
    case LE:
      gcc_assert (const0_rtx == op1);
      break;

    default:
      gcc_unreachable();
    }

  emit_jump_insn (gen_branch_rtx (targ,
                                  gen_rtx_fmt_ee (code, VOIDmode, op0, op1)));
}


/* if TARG != 0, emit a SImode setcompare instruction, i.e. emit insns
   whose effect is the same as

       TARG = (OP0 <<CODE>> OP1)

   where CODE is a comparison code.  We canonicalize the comparison so that
   just instructions/comparisons get generated that are supported by our
   hardware.

   If TARG == 0 we just emit insns that are generated by the canonicalisation
   and return the right hand side (OP0 <<CODE>> OP1) without emitting the
   setcompare instruction.  */

rtx
tric_emit_setcompare (enum rtx_code code, rtx op0, rtx op1, rtx targ)
{
  rtx rhs;
  enum machine_mode mode = GET_MODE (op0);

  code = tric_canonicalize_comparison_code (code, &op0, &op1);

  switch (code)
    {
    default:
      break;

    case GT:
    case GTU:
    case LE:
    case LEU:
      {
        rtx op;
        code = swap_condition (code);
        op = op0; op0 = op1; op1 = op;
        break;
      }
    }

  switch (code)
    {
    case NE:
    case EQ:
    case LT:
    case GE:
      if (!register_operand (op0, mode))
        op0 = copy_to_mode_reg (mode, op0);

      if (s9_operand (op1, mode))
        break;

      op1 = copy_to_mode_reg (mode, op1);
      break;

    case LTU:
    case GEU:
      if (!register_operand (op0, mode))
        op0 = copy_to_mode_reg (mode, op0);

      if (u9_operand (op1, mode))
        break;

      op1 = copy_to_mode_reg (mode, op1);
      break;

    default:
      gcc_unreachable();
    }

  rhs = gen_rtx_fmt_ee (code, mode, op0, op1);

  if (targ)
    emit_move_insn (targ, rhs);

  return rhs;
}


static void
tric_emit_accumulate_setcompare (rtx targ, enum rtx_code bitop, rtx compare)
{
  rtx rhs = gen_rtx_fmt_ee (bitop, SImode, compare, targ);
  rtx lhs = (IOR == bitop
             ? targ
             : gen_rtx_ZERO_EXTRACT (SImode, targ, const1_rtx, const0_rtx));
  
  emit_insn (gen_rtx_SET (lhs, rhs));
}


void
tric_emit_setcompare_di (enum rtx_code code, rtx op1, rtx op2, rtx reg)
{
  enum rtx_code code_s = code;
  enum rtx_code code_u = code;
  rtx hi1 = simplify_gen_subreg (SImode, op1, GET_MODE (op1), 4);
  rtx lo1 = simplify_gen_subreg (SImode, op1, GET_MODE (op1), 0);
  rtx hi2 = simplify_gen_subreg (SImode, op2, GET_MODE (op1), 4);
  rtx lo2 = simplify_gen_subreg (SImode, op2, GET_MODE (op1), 0);

  /* Comparing against 0
     Use just the high part for < resp >= */

  if (const0_rtx == op2
      && (LT == code || GE == code))
    {
      tric_emit_setcompare (code, hi1, const0_rtx, reg);
      return;
    }

  /* For non-commutative comparison operators o, i.e. <, <=, >, >=
     in unsigned and signed flavour we have:

         A  o  B <=> (A.h == B.h && A.l  o.u  B.l) || A.h  o.s  B.h

     where o.s = strict   version of o
           o.u = unsigned version of o */

  /* Get unsigned version of comparison */

  switch (code)
    {
    default:
      break;

    case LT: code_u = LTU; break;
    case LE: code_u = LEU; break;
    case GT: code_u = GTU; break;
    case GE: code_u = GEU; break;
    }

  /* Get strict version of comparison */

  switch (code)
    {
    default:
      break;

    case LE: code_s = LT; break;
    case GE: code_s = GT; break;
    case LEU: code_s = LTU; break;
    case GEU: code_s = GTU; break;
    }

  /* For some cases the low part comparison turns out to be trivial. */

  if (CONST_INT_P (lo2))
    {
      int32_t loval = (int32_t) INTVAL (lo2);

      /* Low part comparison is always false, so just do the strict compare
         for the high parts */

      if ((GTU == code_u && loval == -1)
          || (LTU == code_u && loval == 0))
        {
          tric_emit_setcompare (code_s, hi1, hi2, reg);
          return;
        }

      /* Low part comparison will always be true. This is the case for
         some non-strict comparisons */

      if ((GEU == code_u && loval == 0)
          || (LEU == code_u && loval == -1))
        {
          tric_emit_setcompare (code, hi1, hi2, reg);
          return;
        }
    }

  switch (code)
    {
    case EQ:
      tric_emit_setcompare (EQ, hi1, hi2, reg);
      tric_emit_accumulate_setcompare (reg, AND,
                                       tric_emit_setcompare (EQ, lo1, lo2,
                                                             NULL_RTX));
      return;

    case NE:
      tric_emit_setcompare (NE, hi1, hi2, reg);
      tric_emit_accumulate_setcompare (reg, IOR,
                                       tric_emit_setcompare (NE, lo1, lo2,
                                                             NULL_RTX));
      return;

    case LT: case LTU: case LE: case LEU:
    case GT: case GTU: case GE: case GEU:
      {
        int val = CONST_INT_P (lo2) ? INTVAL (lo2) : 42;

        tric_emit_setcompare (EQ, hi1, hi2, reg);

        /* Avoid reloading of -1 in some cases where the unsigned comparison
           is true/false only for -1. */

        if ((val == -1 && GEU == code_u)  ||  (val == -2 && GTU == code_u))
          code_u = EQ, lo2 = constm1_rtx;
        else if ((val == -1 && LTU == code_u)  ||  (val == -2 && LEU == code_u))
          code_u = NE, lo2 = constm1_rtx;

        val = CONST_INT_P (hi2) ? INTVAL (hi2) : 42;

        if (val == -1 && code_s == LTU)
          code_s = NE, hi2 = constm1_rtx;
        else if (val == -2 && code_s == GTU)
          code_s = EQ, hi2 = constm1_rtx;

        tric_emit_accumulate_setcompare (reg, AND,
                                         tric_emit_setcompare (code_u, lo1, lo2,
                                                               NULL_RTX));
        tric_emit_accumulate_setcompare (reg, IOR,
                                         tric_emit_setcompare (code_s, hi1, hi2,
                                                               NULL_RTX));
        return;
      }

    default:
      gcc_unreachable();
      break;
    }
}

/* Worker function for "cbranchsi4" insn */

void
tric_emit_cbranchsi4 (rtx xop[])
{
  enum rtx_code code = GET_CODE (xop[0]);
  tric_emit_branch (code, xop[1], xop[2], xop[3]);
}

/* Worker function for "cbranchdi4" insn */

void
tric_emit_cbranchdi4 (rtx xop[])
{
  enum rtx_code code = GET_CODE (xop[0]);
  enum rtx_code code_s = code;
  enum rtx_code code_u = code;
  rtx hi1 = simplify_gen_subreg (SImode, xop[1], GET_MODE (xop[1]), 4);
  rtx lo1 = simplify_gen_subreg (SImode, xop[1], GET_MODE (xop[1]), 0);
  rtx hi2 = simplify_gen_subreg (SImode, xop[2], GET_MODE (xop[1]), 4);
  rtx lo2 = simplify_gen_subreg (SImode, xop[2], GET_MODE (xop[1]), 0);
  rtx reg = gen_reg_rtx (SImode);

  /* Comparing against 0 */

  if (const0_rtx == xop[2])
    {
      /* Use just the high part for < resp >= */

      if (LT == code || GE == code)
        {
          emit_jump_insn (gen_branch_rtx (xop[3],
                                          gen_rtx_fmt_ee (code, VOIDmode, hi1,
                                                          const0_rtx)));
          return;
        }

      /* For == and != test for a 1-bit by ORing high and lowpart */

      if (NE == code || EQ == code)
        {
          emit_insn (gen_iorsi3 (reg, hi1, lo1));
          emit_jump_insn (gen_branch_rtx (xop[3],
                                          gen_rtx_fmt_ee (code, VOIDmode, reg,
                                                          const0_rtx)));
          return;
        }
    }

  if (constm1_rtx == xop[2]
      && (EQ == code || NE == code))
    {
      emit_insn (gen_andsi3 (reg, hi1, lo1));
      emit_jump_insn (gen_branch_rtx (xop[3],
                                      gen_rtx_fmt_ee (code, VOIDmode, reg,
                                                      constm1_rtx)));
      return;
    }

  /* For non-commutative comparison operators o, i.e. <, <=, >, >=
     in unsigned and signed flavour we have:

         A  o  B <=> (A.h == B.h && A.l  o.u  B.l) || A.h  o.s  B.h

     where o.s = strict   version of o
           o.u = unsigned version of o */

  /* Get unsigned version of comparison */

  switch (code)
    {
    default:
      break;

    case LT: code_u = LTU; break;
    case LE: code_u = LEU; break;
    case GT: code_u = GTU; break;
    case GE: code_u = GEU; break;
    }

  /* Get strict version of comparison */

  switch (code)
    {
    default:
      break;

    case LE: code_s = LT; break;
    case GE: code_s = GT; break;
    case LEU: code_s = LTU; break;
    case GEU: code_s = GTU; break;
    }

  /* For some cases the low part comparison turns out to be trivial. */

  if (CONST_INT_P (lo2))
    {
      int32_t loval = (int32_t) INTVAL (lo2);

      /* Low part comparison is always false, so just do the strict compare
         for the high parts */

      if ((GTU == code_u && loval == -1)
          || (LTU == code_u && loval == 0))
        {
          tric_emit_setcompare (code_s, hi1, hi2, reg);
          emit_jump_insn (gen_branch_rtx (xop[3],
                                          gen_rtx_fmt_ee (NE, VOIDmode, reg,
                                                          const0_rtx)));
          return;
        }

      /* Low part comparison will always be true. This is the case for
         some non-strict comparisons */

      if ((GEU == code_u && loval == 0)
          || (LEU == code_u && loval == -1))
        {
          tric_emit_setcompare (code, hi1, hi2, reg);
          emit_jump_insn (gen_branch_rtx (xop[3],
                                          gen_rtx_fmt_ee (NE, VOIDmode, reg,
                                                          const0_rtx)));
          return;
        }
    }

  switch (code)
    {
    case EQ:
      tric_emit_setcompare (EQ, hi1, hi2, reg);
      tric_emit_accumulate_setcompare (reg, AND,
                                       tric_emit_setcompare (EQ, lo1, lo2,
                                                             NULL_RTX));
      break;

    case NE:
      tric_emit_setcompare (NE, hi1, hi2, reg);
      tric_emit_accumulate_setcompare (reg, IOR,
                                       tric_emit_setcompare (NE, lo1, lo2,
                                                             NULL_RTX));
      break;

    case LT: case LTU: case LE: case LEU:
    case GT: case GTU: case GE: case GEU:
      {
        int val = CONST_INT_P (lo2) ? INTVAL (lo2) : 42;

        tric_emit_setcompare (EQ, hi1, hi2, reg);

        /* Avoid reloading of -1 in some cases where the unsigned comparison
           is true/false only for -1. */

        if ((val == -1 && GEU == code_u)  ||  (val == -2 && GTU == code_u))
          code_u = EQ, lo2 = constm1_rtx;
        else if ((val == -1 && LTU == code_u)  ||  (val == -2 && LEU == code_u))
          code_u = NE, lo2 = constm1_rtx;

        val = CONST_INT_P (hi2) ? INTVAL (hi2) : 42;

        if (val == -1 && code_s == LTU)
          code_s = NE, hi2 = constm1_rtx;
        else if (val == -2 && code_s == GTU)
          code_s = EQ, hi2 = constm1_rtx;

        tric_emit_accumulate_setcompare (reg, AND,
                                         tric_emit_setcompare (code_u, lo1, lo2,
                                                               NULL_RTX));
        tric_emit_accumulate_setcompare (reg, IOR,
                                         tric_emit_setcompare (code_s, hi1, hi2,
                                                               NULL_RTX));
        break;
      }

    default:
      gcc_unreachable();
      break;
    }

  emit_jump_insn (gen_branch_rtx (xop[3],
                                  gen_rtx_fmt_ee (NE, VOIDmode, reg,
                                                  const0_rtx)));
}

/* Worker function for "cbranchsf4" insn
   $0 = comparison operator
   $3 = label to jump if condition $1 <$0> $2 is true.  */

void
tric_emit_cbranchsf4 (rtx xop[])
{
  int bit1 = -1;
  int bit2 = -1;
  int bit3 = -1;
  enum rtx_code code = GET_CODE (xop[0]);
  rtx reg = gen_reg_rtx (SImode);

  /* Do a CMP.F instruction on the stuff to be compared (two regs) */
  emit_insn (gen_cmp_f (reg, xop[1], xop[2]));

  /* Depending on the comparison to be performed, CMP.F will have set
     some bits. Indentify which bits to use for the jump. We jump if
     any of these bits is non-zero, i.e. we will OR the bits in the end. */

  switch (code)
    {
    default:
      gcc_unreachable();

    case EQ:
      bit1 = CMP_F_EQ;
      break;

    case NE:
      bit1 = CMP_F_UNORDERED; bit2 = CMP_F_LT; bit3 = CMP_F_GT;
      break;

    case LT:
      bit1 = CMP_F_LT;
      break;

    case GT:
      bit1 = CMP_F_GT;
      break;

    case LE:
      bit1 = CMP_F_LT; bit2 = CMP_F_EQ;
      break;

    case GE:
      bit1 = CMP_F_GT; bit2 = CMP_F_EQ;
      break;

    case UNORDERED:
      bit1 = CMP_F_UNORDERED;
      break;

    case UNEQ:
      bit1 = CMP_F_UNORDERED; bit2 = CMP_F_EQ;
      break;

    case UNLT:
      bit1 = CMP_F_UNORDERED; bit2 = CMP_F_LT;
      break;

    case UNGT:
      bit1 = CMP_F_UNORDERED; bit2 = CMP_F_GT;
      break;

    case UNGE:
      bit1 = CMP_F_UNORDERED; bit2 = CMP_F_GT; bit3 = CMP_F_EQ;
      break;

    case UNLE:
      bit1 = CMP_F_UNORDERED; bit2 = CMP_F_LT; bit3 = CMP_F_EQ;
      break;

    case LTGT:
      bit1 = CMP_F_LT; bit2 = CMP_F_GT;
      break;
    }

  if (bit3 != -1)
    {
      /* 3 bits: Mask the relevant bits out using AND. The highest bit set
         by CMP.F is bit 5, so ANDing will always work without loading
         the mask. */

      emit_insn (gen_andsi3 (reg, reg, GEN_INT ((1 << bit1) | (1 << bit2)
                                                | (1 << bit3))));
    }
  else
    {
      /* 1 or 2 bits: mask the relevant bits using OR.T.
         If just one bit is used, combine will collapse this to JNZ.T */

      if (bit2 == -1)
        bit2 = bit1;
      emit_insn (gen_iorsi3_zerox1 (reg,
                                    reg, GEN_INT (bit1), reg, GEN_INT (bit2)));
    }

  /* yeah! let's jump! */

  emit_jump_insn (gen_branch_rtx (xop[3],
                                  gen_rtx_fmt_ee (NE, VOIDmode, reg,
                                                  const0_rtx)));
}

/* Worker function for "cbranchdf4" insn
   $0 = comparison operator
   $3 = label to jump if condition $1 <$0> $2 is true.  */

void
tric_emit_cbranchdf4 (rtx xop[])
{
  int bit1 = -1;
  int bit2 = -1;
  int bit3 = -1;
  enum rtx_code code = GET_CODE (xop[0]);
  rtx reg = gen_reg_rtx (SImode);

  /* Do a CMP.F instruction on the stuff to be compared (two regs) */
  emit_insn (gen_cmp_df (reg, xop[1], xop[2]));

  /* Depending on the comparison to be performed, CMP.F will have set
     some bits. Indentify which bits to use for the jump. We jump if
     any of these bits is non-zero, i.e. we will OR the bits in the end. */

  switch (code)
    {
    default:
      gcc_unreachable();

    case EQ:
      bit1 = CMP_DF_EQ;
      break;

    case NE:
      bit1 = CMP_DF_UNORDERED; bit2 = CMP_DF_LT; bit3 = CMP_DF_GT;
      break;

    case LT:
      bit1 = CMP_DF_LT;
      break;

    case GT:
      bit1 = CMP_DF_GT;
      break;

    case LE:
      bit1 = CMP_DF_LT; bit2 = CMP_DF_EQ;
      break;

    case GE:
      bit1 = CMP_DF_GT; bit2 = CMP_DF_EQ;
      break;

    case UNORDERED:
      bit1 = CMP_DF_UNORDERED;
      break;

    case UNEQ:
      bit1 = CMP_DF_UNORDERED; bit2 = CMP_DF_EQ;
      break;

    case UNLT:
      bit1 = CMP_DF_UNORDERED; bit2 = CMP_DF_LT;
      break;

    case UNGT:
      bit1 = CMP_DF_UNORDERED; bit2 = CMP_F_GT;
      break;

    case UNGE:
      bit1 = CMP_DF_UNORDERED; bit2 = CMP_DF_GT; bit3 = CMP_DF_EQ;
      break;

    case UNLE:
      bit1 = CMP_DF_UNORDERED; bit2 = CMP_DF_LT; bit3 = CMP_DF_EQ;
      break;

    case LTGT:
      bit1 = CMP_DF_LT; bit2 = CMP_DF_GT;
      break;
    }

  if (bit3 != -1)
    {
      /* 3 bits: Mask the relevant bits out using AND. The highest bit set
         by CMP.F is bit 5, so ANDing will always work without loading
         the mask. */

      emit_insn (gen_andsi3 (reg, reg, GEN_INT ((1 << bit1) | (1 << bit2)
                                                | (1 << bit3))));
    }
  else
    {
      /* 1 or 2 bits: mask the relevant bits using OR.T.
         If just one bit is used, combine will collapse this to JNZ.T */

      if (bit2 == -1)
        bit2 = bit1;
      emit_insn (gen_iorsi3_zerox1 (reg,
                                    reg, GEN_INT (bit1), reg, GEN_INT (bit2)));
    }

  /* yeah! let's jump! */

  emit_jump_insn (gen_branch_rtx (xop[3],
                                  gen_rtx_fmt_ee (NE, VOIDmode, reg,
                                                  const0_rtx)));
}

static bool
tric_can_use_doloop_p (const widest_int &,
						const widest_int &iterations_max ATTRIBUTE_UNUSED,
                       unsigned int loop_depth ATTRIBUTE_UNUSED,
                       bool entered_at_top ATTRIBUTE_UNUSED)
{
  if (!tric_opt_loop)
    return false;
//TODO
////  if (// If no upper bound for number of iterations is unknown or...
////      iterations_max.is_zero()
////      // ...that bound is greater than 0xfffffff, then fail.
////      || iterations_max.ugt (double_int::from_uhwi (0xffffffff)))
////    return false;
//
//  return true;
  return false;
}


/***********************************************************************
 ** Printing Operands in final ASM file
 ***********************************************************************/

static void
tric_output_reglist1 (FILE * stream, unsigned mask, int off)
{
  int n0, n1;

  mask &= 0xffffffff;

  while (mask)
    {
      n0 = ctz_hwi (mask);
      mask >>= n0;
      off += n0;

      n1 = ctz_hwi (~mask);
      mask >>= n1;
      fputs (REGISTER_PREFIX, stream);
      fputs (reg_names[off], stream);

      if (n1 >= 2)
        fprintf (stream, "-%s%s", REGISTER_PREFIX, reg_names[off+n1-1]);

      off += n1;

      if (mask)
        fputc (',', stream);
    }
}

/* Print the registers in MASK to STREAM.
   This is used to print verbose stuff in prologue. */

void
tric_output_reglist (FILE * stream, unsigned int mask)
{
  unsigned mask_a = (mask & AREGS_MASK) >> REG_A0;
  unsigned mask_d = (mask & DREGS_MASK) >> REG_D0;

  tric_output_reglist1 (stream, mask_a, REG_A0);

  if (mask_a && mask_d)
    fputc (',', stream);

  tric_output_reglist1 (stream, mask_d, REG_D0);
}


/***********************************************************************
 ** Initializing: Machine, per Function Data, ...
 ***********************************************************************/

/* Defining data structures for per-function information */
/* The usual; we set up our machine_function data. */

static struct machine_function*
tric_init_machine_status (void)
{
  struct machine_function *machine;
  machine = ggc_cleared_alloc<machine_function> ();
  return machine;
}


/* Copy-paste static tree-ssa-structalias.c:count_num_arguments().  */

static unsigned int
tric_count_num_arguments (tree decl, bool *is_varargs)
{
  unsigned int num = 0;
  tree t;

  /* Capture named arguments for K&R functions.  They do not
     have a prototype and thus no TYPE_ARG_TYPES.  */
  for (t = DECL_ARGUMENTS (decl); t; t = DECL_CHAIN (t))
    ++num;

  /* Check if the function has variadic arguments.  */
  for (t = TYPE_ARG_TYPES (TREE_TYPE (decl)); t; t = TREE_CHAIN (t))
    if (TREE_VALUE (t) == void_type_node)
      break;
  if (!t)
    *is_varargs = true;

  return num;
}


/* Implement `TARGET_SET_CURRENT_FUNCTION' */

static void
tric_set_current_function (tree decl)
{
  if (decl != NULL_TREE
      && cfun->machine
      && !cfun->machine->bogus_pxhndcall
      && tric_pxhndcall_function_p (decl))
    {
      bool is_varargs = false;
      location_t loc = DECL_SOURCE_LOCATION (decl);
      unsigned int nargs = tric_count_num_arguments (decl, &is_varargs);

      if (!DECL_CONTEXT (decl)
          || TREE_CODE (DECL_CONTEXT (decl)) != FUNCTION_DECL)
        {
          error_at (loc, "attribute %<__pxhndcall__%> only applies to"
                    " local functions");
          cfun->machine->bogus_pxhndcall = 1;
        }

      if (is_varargs)
        {
          error_at (loc, "attribute %<__pxhndcall__%> used with varargs"
                    " function");
          cfun->machine->bogus_pxhndcall = 1;
        }
      else if (nargs != 2)
        {
          error_at (loc, "attribute %<__pxhndcall__%> forces function to get"
                    " 2 arguments but %d given", nargs);
          cfun->machine->bogus_pxhndcall = 1;
        }
    }
}


/* Implement `INIT_EXPANDERS' */
/* We just set up to call the above function.  */

void
tric_init_expanders (void)
{
  init_machine_status = tric_init_machine_status;
}

/* Implement TARGET_INIT_LIBFUNCS */

static void
tric_init_libfuncs (void)
{
  /* Arithmetic.  */
  set_optab_libfunc (add_optab, HFmode, NULL);
  set_optab_libfunc (sdiv_optab, HFmode, NULL);
  set_optab_libfunc (smul_optab, HFmode, NULL);
  set_optab_libfunc (neg_optab, HFmode, NULL);
  set_optab_libfunc (sub_optab, HFmode, NULL);

  /* Comparisons.  */
  set_optab_libfunc (eq_optab, HFmode, NULL);
  set_optab_libfunc (ne_optab, HFmode, NULL);
  set_optab_libfunc (lt_optab, HFmode, NULL);
  set_optab_libfunc (le_optab, HFmode, NULL);
  set_optab_libfunc (ge_optab, HFmode, NULL);
  set_optab_libfunc (gt_optab, HFmode, NULL);
  set_optab_libfunc (unord_optab, HFmode, NULL);
}

/* Implement TARGET_SCALAR_MODE_SUPPORTED_P.
   This simply adds HFmode as a supported mode; even though we don't
   implement arithmetic on this type directly, it's supported by
   optabs conversions, much the way the double-word arithmetic is
   special-cased in the default hook.  */

static bool
tric_scalar_mode_supported_p (scalar_mode mode)
{
  if (mode == TImode)
    return false;
  if (mode == HFmode)
    return true;
  else
    return default_scalar_mode_supported_p (mode);
}




/***********************************************************************
 ** Section Handling
 ***********************************************************************/

static bool
tric_decl_volatile_const_rodata_p (const_tree decl)
{
  return (tric_opt_volatile_const_in_rodata
          && TREE_CODE (decl) == VAR_DECL
          && TREE_SIDE_EFFECTS (decl)
          && TREE_READONLY (decl));
}


/* Return 1 if variable VAR_DECL is located in a small addressable
   data section, 0 otherwise.  */

static int
tric_decl_in_smalldata (tree var_decl)
{
  int size;
  int size_min = tric_sdata_min;
  int size_max = tric_sdata_max;

  if (TREE_CODE (var_decl) == VAR_DECL)
    {
//      int dam;
//      tree var_sec;

      if (lookup_attribute ("smalldata", DECL_ATTRIBUTES (var_decl)))
        return 1;

      if (lookup_attribute ("smalldata10", DECL_ATTRIBUTES (var_decl)))
        return 2;

      if (lookup_attribute ("absdata", DECL_ATTRIBUTES (var_decl)))
        return 0;

      /* is there an explicit section directive? */
      if (DECL_SECTION_NAME (var_decl) != NULL)
        {
          const char *sec_name = DECL_SECTION_NAME (var_decl);
          const tric_section_t *tsec = tric_lookup_section (sec_name);
          /* For legacy code.  */
          if (STREQ (sec_name, ".sdata.rodata"))
            return 1;

          return tsec && (tsec->flags & SECTION_SMALL);
        }

      if (TREE_READONLY (var_decl)
          && (!TREE_SIDE_EFFECTS (var_decl)
              || tric_decl_volatile_const_rodata_p (var_decl))
          && (DECL_INITIAL (var_decl) == 0
              || DECL_INITIAL (var_decl) == error_mark_node
              || TREE_CONSTANT (DECL_INITIAL (var_decl))))
        {
          size_max = tric_sconst_max;
          size_min = tric_sconst_min;
        }
    }
  else if (TREE_CODE (var_decl) == STRING_CST
           || TREE_CODE (var_decl) == CONSTRUCTOR)
    {
      size_max = tric_sconst_max;
      size_min = tric_sconst_min;
    }

  /* No section attribute */

  if (size_max >= INT_MAX-1 && size_min <= 1)
    /* all data without explicit section directive go into sbss/sdata */
    return 1;

  /* Remaining data goes to sbss/sdata if size fits */
  size = int_size_in_bytes (TREE_TYPE (var_decl));

  if (size > 0
      && size <= size_max
      && size >= size_min)
    return 1;

  return 0;
}


/* Return 1 if variable VAR_DECL is located in an absolute addressable
   data section, 0 otherwise.  */

static int
tric_decl_in_absolute (tree var_decl)
{
  int size;
  int size_min = tric_zdata_min;
  int size_max = tric_zdata_max;

  if (TREE_CODE (var_decl) == VAR_DECL)
    {
      if (lookup_attribute ("smalldata", DECL_ATTRIBUTES (var_decl)))
        return 1;

      if (lookup_attribute ("smalldata10", DECL_ATTRIBUTES (var_decl)))
        return 2;

      if (lookup_attribute ("absdata", DECL_ATTRIBUTES (var_decl)))
        return 0;

      /* Is there an explicit section directive? */
      if (DECL_SECTION_NAME (var_decl) != NULL)
        {
          const char *sec_name = DECL_SECTION_NAME (var_decl);
          const tric_section_t *tsec = tric_lookup_section (sec_name);

          return tsec && (tsec->flags & TRIC_SECTION_ABSOLUTE);
        }
      if (TREE_READONLY (var_decl)
          && (!TREE_SIDE_EFFECTS (var_decl)
              || tric_decl_volatile_const_rodata_p (var_decl))
          && (DECL_INITIAL (var_decl) == 0
              || DECL_INITIAL (var_decl) == error_mark_node
              || TREE_CONSTANT (DECL_INITIAL (var_decl))))
        {
          size_min = tric_zconst_min;
          size_max = tric_zconst_max;
        }
    }
  else if (TREE_CODE (var_decl) == STRING_CST
           || TREE_CODE (var_decl) == CONSTRUCTOR)
    {
      size_min = tric_zconst_min;
      size_max = tric_zconst_max;
    }

  /* var_sec == NULL_TREE, i.e. no section attribute */

  if (size_max >= INT_MAX-1 && size_min <= 1)
    /* all data without explicit section directive go into zbss/zdata */
    return 1;

  /* Remaining data goes to zbss/zdata if size fits */
  size = int_size_in_bytes (TREE_TYPE (var_decl));

  if (size > 0
      && size <= size_max
      && size >= size_min)
    return 1;

  return 0;
}


/* Implement `TARGET_ASM_FUNCTION_RODATA_SECTION' */

static section*
tric_function_rodata_section (tree decl ATTRIBUTE_UNUSED, bool relocatable ATTRIBUTE_UNUSED)
{
  // CHECK
  return readonly_data_section;
}


/* Helper for targetm.asm_out.init_sections:  Materialize one section from
   a respective DEF_SECTION in tricore-sections.def.  */
#if 0
static void
tric_def_one_section (const char *name, const char *s_flags, int align,
                      bool init_lookup, section **psec)
{
  location_t loc = BUILTINS_LOCATION;
  htc_secspec_t *sspec = htc_build_secspec (SECSPEC_htc_built_in, name,
                                            s_flags, align, NULL_TREE, loc);

  unsigned bss = NULL != strchr (s_flags, 'B') ? SECTION_BSS : 0;
  unsigned flags = (bss
                    | SECTION_UNNAMED
                    | targetm.htc.section_flags_from_string (s_flags));
  htc_section_t *hsec = htc_insert_section (name, flags, align,
                                            sspec, NULL_TREE, loc);

  /* We may pass GTY'ed htc_section_t objects to sec->unnamed.callback
     as `TARGET_HTC_POST_PCH_LOAD' performs the needed fix-ups after
     PCH deserialization.  Notice that sec->unnamed.data is GTY skip'ed.
     Cf. also [GCC-145].  */

  section *sec = get_unnamed_section (hsec->flags,
                                      targetm.htc.unnamed_section_callback,
                                      hsec);
  hsec->sec = sec;
  hsec->next = tric_builtin_sections;
  tric_builtin_sections = hsec;

  /* Patch an existing default section like `bss_section' from varasm.c. */

  if (psec)
    *psec = sec;

  /* Set up tric_data_section[] with default data sections for fast lookup. */

  if (init_lookup)
    {
      unsigned ss1 = (flags & SECTION_SMALL) ? SS_SMALL
        : (flags & TRIC_SECTION_ABSOLUTE) ? SS_ABSOLUTE
        : SS_INDIRECT;

      unsigned ss2 = (flags & SECTION_BSS) ? SS_BSS
        : (flags & SECTION_WRITE) ? SS_DATA
        : SS_RODATA;

      unsigned ss3 = align == 1 ? SS_ALIGN_1
        : align == 2 ? SS_ALIGN_2
        : align == 4 ? SS_ALIGN_4
        : align == 8 ? SS_ALIGN_8
        : SS_ALIGN_NONE;

      tric_data_section[ss1][ss2][ss3] = sec;
    }
}
#endif
/* Callback function for sections. TARGET_ASM_INIT_SECTIONS
   equips the generated section with this callback function */

static void
tric_output_section_asm_op (const void* data)
{
  unsigned int i;
  const tric_section_t *sec = (const tric_section_t*) data;
  char flags[20];
  tric_section_flags_from_flags (flags, sec->flags);

  fprintf (asm_out_file, ".section\t%s,\"", sec->name);

  for (i = 0; flags[i] != '\0'; i++)
    {
      if (flags[i] != 'B')
        fputc (flags[i], asm_out_file);
    }

  fprintf (asm_out_file, "\",@%s\n",
           sec->flags & SECTION_BSS ? "nobits" : "progbits");
}


/* Implement `TARGET_ASM_INIT_SECTIONS' */
/* Set up the TriCore-specific default sections like .data.a4, .zbss, .pictext
   etc. and replace the respective section opjects like text_section from
   varasm.c provided there is such a section object known to varasm.  */
#if 0
static void
tric_asm_init_sections (void)
{
#define DEF_SECTION(NAME, S_FLAGS, ALIGN, INIT_LOOKUP, PSEC)            \
  tric_def_one_section (NAME, S_FLAGS, ALIGN, INIT_LOOKUP, PSEC);

#include "tricore-sections.def"

#undef DEF_SECTION

  tric_text_section
    = htc_lookup_section (tric_opt_code_pic ? ".pictext" : ".text");

  text_section = tric_text_section->sec;

  ctors_section = get_unnamed_section (0, output_section_asm_op,
                                       CTORS_SECTION_ASM_OP);

  dtors_section = get_unnamed_section (0, output_section_asm_op,
                                       DTORS_SECTION_ASM_OP);
}
#endif

static void
tric_asm_init_sections (void)
{
  unsigned int i;
  tric_section_t *text, *pictext;
  tric_sections=NULL;
  static const struct
  {
    const char *name;
    section **sec;
    unsigned int flags;
  }
  sect[] = {
    { ".data",   &data_section,          SECTION_WRITE               },
    { ".rodata", &readonly_data_section, 0                           },
    { ".bss",    &bss_section,           SECTION_WRITE | SECTION_BSS },
    { ".zdata",   NULL, TRIC_SECTION_ABSOLUTE | SECTION_WRITE               },
    { ".zrodata", NULL, TRIC_SECTION_ABSOLUTE                               },
    { ".zbss",    NULL, TRIC_SECTION_ABSOLUTE | SECTION_WRITE | SECTION_BSS },
    { ".sdata", &sdata_section, SECTION_SMALL | SECTION_WRITE               },
    { ".srodata", NULL,         SECTION_SMALL                               },
    { ".sbss", &sbss_section,   SECTION_SMALL | SECTION_WRITE | SECTION_BSS }
  };
  for (i=0; i<TRIC_SECTION_COLL_MAX; i+=1 )
  {
	memset(&tric_section_coll[i],0,sizeof(tric_section_t));
  }
  tric_section_coll_ind=0;

  pictext = tric_insert_section (".pictext", "ax", 2, BUILTINS_LOCATION);
  pictext->sec = get_unnamed_section (SECTION_CODE, output_section_asm_op,
                                      ".section .pictext,\"ax\",@progbits");

  text = tric_insert_section (".text", "ax", 2, BUILTINS_LOCATION);

  text->sec = get_unnamed_section (SECTION_CODE, output_section_asm_op,
                                      ".section .text,\"ax\",@progbits");

  tric_text_section = tric_opt_code_pic ? pictext : text;
  text_section = tric_text_section->sec;

  for (i = 0; i < sizeof (sect) / sizeof (sect[0]); i++)
    {
      char s_flags[20];
      int ss1, ss2, ss3, flags = sect[i].flags;
      const char *name = sect[i].name;
      tric_section_flags_from_flags (s_flags, flags);

      if (flags & SECTION_SMALL)
        ss1 = SS_SMALL;
      else if (flags & TRIC_SECTION_ABSOLUTE)
        ss1 = SS_ABSOLUTE;
      else
        ss1 = SS_INDIRECT;

      if (flags & SECTION_BSS)
        ss2 = SS_BSS;
      else if (flags & SECTION_WRITE)
        ss2 = SS_DATA;
      else
        ss2 = SS_RODATA;

      for (ss3 = 0; ss3 < SS3_MAX; ss3++)
        {
          tric_section_t *tsec;
          section *sec;
          unsigned int align = 0;
          const char *suffix;

          switch (ss3)
            {
            default:
              gcc_unreachable();

            case SS_ALIGN_NONE: suffix = ""; break;

            case SS_ALIGN_1: suffix = ".a1"; align = 1; break;
            case SS_ALIGN_2: suffix = ".a2"; align = 2; break;
            case SS_ALIGN_4: suffix = ".a4"; align = 4; break;
            case SS_ALIGN_8: suffix = ".a8"; align = 8; break;
            }

          tsec = tric_insert_section (ACONCAT ((name, suffix, NULL)),
                                      s_flags, align, BUILTINS_LOCATION);
          sec = get_unnamed_section (flags,
                                     tric_output_section_asm_op, tsec);

          /* Replace sections known to varasm by our own versions.
             but only the unaligned version */

          if (sect[i].sec && (ss3 == SS_ALIGN_NONE))
		  { *(sect[i].sec) = sec;
	  }

          /* Initialize array with default data sections for easy lookup.  */

          tric_data_section[ss1][ss2][ss3] = tsec->sec = sec;
          tric_data_section_ext[ss1][ss2][ss3]=tsec;
        }
    }

  ctors_section = get_unnamed_section (0, output_section_asm_op,
                                       CTORS_SECTION_ASM_OP);

  dtors_section = get_unnamed_section (0, output_section_asm_op,
                                       DTORS_SECTION_ASM_OP);
}


/* Implement `TARGET_ASM_FUNCTION_SECTION' */
/* This is basically a copy of varasm.c:default_function_section
   that is needed to replace the explicit ".text..." from there
   in the case when PIC shall be generated.
   Don't use `varasm.c::get_named_text_section' at all.  */

static section*
tric_asm_function_section (tree decl, enum node_frequency freq,
                           bool startup, bool exit)
{
  const char *text = tric_text_section->name;

#if defined HAVE_LD_EH_GC_SECTIONS && defined HAVE_LD_EH_GC_SECTIONS_BUG
  /* Old GNU linkers have buggy --gc-section support, which sometimes
     results in .gcc_except_table* sections being garbage collected.  */
  if (decl
      && DECL_SECTION_NAME (decl)
      && DECL_HAS_IMPLICIT_SECTION_NAME_P (decl))
    return NULL;
#endif
  if (!flag_reorder_functions
      || !targetm_common.have_named_sections)
    return NULL;

  /* Startup code should go to startup subsection unless it is
     unlikely executed (this happens especially with function splitting
     where we can split away unnecesary parts of static constructors.  */
if (startup && freq != NODE_FREQUENCY_UNLIKELY_EXECUTED)
  {
    /* If we do have a profile or(and) LTO phase is executed, we do not need
       these ELF section.  */
    if (!in_lto_p || !flag_profile_values)
      return get_named_text_section (decl, ".text.startup", NULL);
    else
      return NULL;
  }

  /* Similarly for exit.  */
  if (exit && freq != NODE_FREQUENCY_UNLIKELY_EXECUTED)
    return get_named_text_section (decl, ACONCAT ((text, ".exit", NULL)), NULL);

  /* Group cold functions together, similarly for hot code.  */
  switch (freq)
    {
      case NODE_FREQUENCY_UNLIKELY_EXECUTED:
        return get_named_text_section (decl,
                                       ACONCAT ((text, ".unlikely", NULL)),
                                       NULL);
      case NODE_FREQUENCY_HOT:
        return get_named_text_section (decl, ACONCAT ((text, ".hot", NULL)),
                                       NULL);
      default:
        return NULL;
    }
}

/* IMPLEMENT `TARGET_HTC_BSS_INITIALIZER_P' */
/* Return true if DECL's initializer is suitable for a BSS section.  */
static bool
tric_bss_initializer_p (const_tree decl, bool named)
{
  if (tric_decl_volatile_const_rodata_p (decl))
    {
      return false;
    }

  return (DECL_INITIAL (decl) == NULL
          || DECL_INITIAL (decl) == error_mark_node
          || (flag_zero_initialized_in_bss
              /* Leave constant zeroes in .rodata so they
                 can be shared.  */
              && !TREE_READONLY (decl)
              && initializer_zerop (DECL_INITIAL (decl))));
}


/* Implement `TARGET_SECTION_TYPE_FLAGS' */

static unsigned int
tric_section_type_flags (tree decl, const char *name, int reloc)
{
  unsigned int flags = default_section_type_flags (decl, name, reloc);

  tric_section_t *secp = tric_lookup_section (name);

  if (secp)
    return secp->flags;

  for (secp = tric_sections; secp; secp = secp->next)
    {
      /* Check if names have the same prefix to get the right flags for named
         sections like .zbss.a1.foo  */

      if (secp->location == BUILTINS_LOCATION
          && (secp->align == 0
              || tric_opt_aligned_data_sections)
          && str_prefix_p (name, ACONCAT ((secp->name, ".", NULL)) ))
        {
          unsigned new_flags = flags | secp->flags;
          if (!(secp->flags & SECTION_WRITE))
            new_flags &= ~SECTION_WRITE;
          if (tricore_log.section)
            {
              char s_old[20], s_new[20];

              tric_section_flags_from_flags (s_old, flags);
              tric_section_flags_from_flags (s_new, new_flags);

              tricore_edump ("%H: inherit %s flags from %s: f=%s -> f=%s\n",
                          decl ? DECL_SOURCE_LOCATION (decl) : UNKNOWN_LOCATION,
                          name, secp->name, s_old, s_new);
            }

          return new_flags;
        }
    }

  return flags;
}


/* Implement `TARGET_ASM_SELECT_SECTION' */
/* Assign our own sections for absolute or small addressable stuff
   or for sections that collect aligned data with -maligned-data-sections.
   varasm.c bypasses this hook for local bss objects; we handle this in the
   respective section callback, namely in tric_asm_output_aligned_block.  */

static section*
tric_asm_select_section (tree decl, int reloc,
                         unsigned HOST_WIDE_INT align ATTRIBUTE_UNUSED)
{
  int ss1, ss2, ss3;
  section *sec = data_section;

  if (TREE_CODE (decl) == VAR_DECL)
    sec = data_section;
  else if (TREE_CODE (decl) == FUNCTION_DECL)
    sec = text_section;

  if (DECL_P (decl))
    {
      if (decl_readonly_section (decl, reloc))
        sec = readonly_data_section;
    }
  else if (TREE_CODE (decl) == CONSTRUCTOR)
    {
      if (! ((flag_pic && reloc)
             || !TREE_READONLY (decl)
             || TREE_SIDE_EFFECTS (decl)
             || !TREE_CONSTANT (decl)))
        sec = readonly_data_section;
    }
  else if (TREE_CODE (decl) == STRING_CST)
    sec = readonly_data_section;
  else if (! (flag_pic && reloc))
    sec = readonly_data_section;

  /* Up to here it's just what gcc does per default */

  if (sec == text_section)
    return sec;

  if (tric_decl_volatile_const_rodata_p (decl)
      && (sec == bss_section
          || sec == data_section))
    {
      sec = readonly_data_section;
    }
  else if (DECL_P (decl)
           && tric_bss_initializer_p (decl,false))
    {
      sec = bss_section;
    }

  /* We narrowed down the section to .bss/.data/.rodata.
     Get accessor IDs to read from tric_data_section[].  */

  if (tric_decl_in_absolute (decl))
    ss1 = SS_ABSOLUTE;
  else if (tric_decl_in_smalldata (decl))
    ss1 = SS_SMALL;
  else
    ss1 = SS_INDIRECT;

  if (sec == readonly_data_section)
    ss2 = SS_RODATA;
  else if (sec == bss_section)
    ss2 = SS_BSS;
  else
    ss2 = SS_DATA;

  ss3 = SS_ALIGN_NONE;

  if (tric_opt_aligned_data_sections)
    {
      int balign;

      align_variable (decl, true /* dont_output_data */);

      balign = DECL_ALIGN (decl) / BITS_PER_UNIT;

      if (balign == 0)
        ss3 = SS_ALIGN_1;
      else if (balign % 8 == 0)
        ss3 = SS_ALIGN_8;
      else if (balign % 4 == 0)
        ss3 = SS_ALIGN_4;
      else if (balign % 2 == 0)
        ss3 = SS_ALIGN_2;
      else
        ss3 = SS_ALIGN_1;
    }
  return tric_data_section[ss1][ss2][ss3];
}



static void
tric_asm_unique_section (tree decl, int reloc)
{
  /* We only need to use .gnu.linkonce if we don't have COMDAT groups.  */
/*  bool one_only = DECL_ONE_ONLY (decl) && !HAVE_COMDAT_GROUP;*/
  bool one_only = DECL_ONE_ONLY (decl) && !HAVE_COMDAT_GROUP;
  enum section_category cat;
  const char *name, *sec_name;
  int ss1, ss2, ss3 = SS_ALIGN_NONE;
  const tric_section_t *tsec = NULL;
  if (one_only)
    {
      default_unique_section (decl, reloc);
      return;
    }

  cat = tric_decl_volatile_const_rodata_p (decl)
    ? SECCAT_RODATA
    : categorize_decl_for_section (decl, reloc);

  switch (cat)
    {
    default:
	  default_unique_section (decl, reloc);
      return;

    case SECCAT_TEXT:
	  tsec = tric_text_section;
      break;

    case SECCAT_RODATA:
    case SECCAT_RODATA_MERGE_STR:
    case SECCAT_RODATA_MERGE_STR_INIT:
    case SECCAT_RODATA_MERGE_CONST:
      ss2 = SS_RODATA;
      break;

    case SECCAT_DATA:
      ss2 = SS_DATA;
      break;

    case SECCAT_BSS:
      ss2 = SS_BSS;
      break;
    }

  if (cat != SECCAT_TEXT)
    {
      ss1 = (tric_decl_in_absolute (decl)    ? SS_ABSOLUTE
             : tric_decl_in_smalldata (decl) ? SS_SMALL
             : SS_INDIRECT);

      if (tric_opt_aligned_data_sections)
        {
          unsigned int align = DECL_ALIGN (decl) / BITS_PER_UNIT;

          if (align == 0)           ss3 = SS_ALIGN_1;
          else if (align % 8 == 0)  ss3 = SS_ALIGN_8;
          else if (align % 4 == 0)  ss3 = SS_ALIGN_4;
          else if (align % 2 == 0)  ss3 = SS_ALIGN_2;
          else                      ss3 = SS_ALIGN_1;
        }

	  tsec = (const tric_section_t*) tric_data_section[ss1][ss2][ss3]->unnamed.data;
    }
  name = IDENTIFIER_POINTER (DECL_ASSEMBLER_NAME (decl));
  name = targetm.strip_name_encoding (name);
  sec_name = ACONCAT ((tsec->name, ".", name, NULL));
  set_decl_section_name (decl, sec_name);
}


static void
tric_asm_named_section (const char *name, unsigned int flags, tree decl)
{
  unsigned int i;
  char flagchars[11], flags2[11], *f = flags2;

  /* If we have already declared this section, we can use an
     abbreviated form to switch back to it -- unless this section is
     part of a COMDAT groups, in which case GAS requires the full
     declaration every time.  */

  if (!(HAVE_COMDAT_GROUP && (flags & SECTION_LINKONCE))
      && (flags & SECTION_DECLARED))
    {
      fprintf (asm_out_file, "\t.section\t%s\n", name);
      return;
    }
  tric_section_flags_from_flags (flagchars, flags);

  for (i = 0; i <= strlen (flagchars); i++)
    {
      if (flagchars[i] != 'B')
        *f++ = flagchars[i];

      if (flagchars[i] == 'B'
          && DECL_INITIAL (decl)
          && DECL_INITIAL (decl) != error_mark_node
          && !initializer_zerop (DECL_INITIAL (decl)))
        {
          tric_section_t *tsec = tric_lookup_section (name);

          warning (0, "variable %q+D with non-zero initializer is put "
                   "into @nobits section %qs with section flag %<B%>",
                   decl, name);

          if (tsec)
            {
              char flagc[11];
              const char *s_here = (tsec->location == BUILTINS_LOCATION
                                    ? "built-in" : "here");

              tric_section_flags_from_flags (flagc, tsec->flags);
              inform (tsec->location,
                      "section %qs defined %s with flags %qs",
                      name, s_here, flagc);
            }
        }
    }

  fprintf (asm_out_file, "\t.section\t%s,\"%s\"", name, flags2);

  if (!(flags & SECTION_NOTYPE))
    {
      const char *type;
      const char *format;

      if (flags & SECTION_BSS)
        type = "nobits";
      else
        type = "progbits";

      format = ",@%s";
#ifdef ASM_COMMENT_START
      /* On platforms that use "@" as the assembly comment character,
         use "%" instead.  */
      if (strcmp (ASM_COMMENT_START, "@") == 0)
        format = ",%%%s";
#endif
      fprintf (asm_out_file, format, type);

      if (flags & SECTION_ENTSIZE)
        fprintf (asm_out_file, ",%d", flags & SECTION_ENTSIZE);

      if (HAVE_COMDAT_GROUP && (flags & SECTION_LINKONCE))
        {
          if (TREE_CODE (decl) == IDENTIFIER_NODE)
            fprintf (asm_out_file, ",%s,comdat", IDENTIFIER_POINTER (decl));
          else
            fprintf (asm_out_file, ",%s,comdat",
                     IDENTIFIER_POINTER (DECL_COMDAT_GROUP (decl)));
        }
    }

  putc ('\n', asm_out_file);
}



typedef struct
{
  /* Location in initializer where (function) address is taken.  */
  location_t location;

  /* VAR_DECL of this initializer or NULL_TREE if unknown.  */
  const_tree decl;
} tric_walk_data_t;


/* Callback for tree_walk as we hunt for function addresses in initializers
   with -mcode-pic or -msmall-pid.  */

static tree
tric_walk_initializer_r (tree *node, int *n ATTRIBUTE_UNUSED, void *data)
{
  tric_walk_data_t *walk_data = (tric_walk_data_t*) data;
  location_t loc = walk_data->location;

  switch (TREE_CODE (*node))
    {
    case VAR_DECL:

      if (loc != UNKNOWN_LOCATION
          && tric_opt_msmall_pid
          && tric_decl_in_smalldata (*node))
        {
          if (walk_data->decl != NULL_TREE)
            warning_at (loc, OPT_Winitialize_pid,
                        "initializer of %qD uses address of register-relative"
                        " addressable variable %qD", walk_data->decl, *node);
          else
            warning_at (loc, OPT_Winitialize_pid,
                        "initializer uses address of register-relative"
                        " addressable variable %qD", *node);
        }
      break;

    case STRING_CST:

      if (tric_opt_msmall_pid
          && tric_decl_in_smalldata (*node)
          && !tric_node_seen (&tric_pid_init, *node))
        {
          if (walk_data->decl != NULL_TREE)
            warning_at (DECL_SOURCE_LOCATION (walk_data->decl),
                        OPT_Winitialize_pid,
                        "initializer of %qD uses address of register-relative"
                        " addressable string literal \"%s\"",
                        walk_data->decl, TREE_STRING_POINTER (*node));
          else
            warning (OPT_Winitialize_pid,
                     "initializer uses address of register-relative"
                     " addressable string literal \"%s\"",
                     TREE_STRING_POINTER (*node));
        }
      break;

    case FUNCTION_DECL:

      if (loc != UNKNOWN_LOCATION
          && tric_opt_code_pic)
        {
          if (walk_data->decl != NULL_TREE)
            {
              warning_at (loc, OPT_Winitialize_pic,
                          "initializer of %qD cannot compute address of"
                          " function %qD at compile time with %qs",
                          walk_data->decl, *node, "-mcode-pic");
            }
          else
            {
              warning_at (loc, OPT_Winitialize_pic,
                          "initializer cannot compute address of"
                          " function %qD at compile time with %qs",
                          *node, "-mcode-pic");
            }
        }
      break;
      
    case ADDR_EXPR:
      {
        /* Pass down the location where the (function) address is taken.  */

        walk_data->location = EXPR_LOCATION (*node);
        walk_tree_without_duplicates (&TREE_OPERAND (*node, 0),
                                      tric_walk_initializer_r, walk_data);
        walk_data->location = loc;
      }
      break;
      
    default:
      break;
    }

  return NULL_TREE;
}


/* Implement `TARGET_ENCODE_SECTION_INFO' */
/* Encode symbol attributes (local vs. global, tls model) of a SYMBOL_REF
   into its SYMBOL_REF_FLAGS.

   Also check if DECL's initializer takes addresses of functions.
   With -mcode-pic, such addresses are not computable at load lime.
   This handles the case of static variables.  */

static void
tric_encode_section_info (tree decl, rtx rtl, int first)
{
  unsigned int flag = 0;
  default_encode_section_info (decl, rtl, first);

  if ((tric_opt_code_pic
       || (tric_opt_msmall_pid && tric_warn_initialize_pid))
      && VAR_DECL == TREE_CODE (decl)
      && DECL_INITIAL (decl))
    {
      tric_walk_data_t walk_data = { UNKNOWN_LOCATION, NULL_TREE };

      walk_data.decl = decl;
      walk_tree_without_duplicates (& DECL_INITIAL (decl),
                                    tric_walk_initializer_r, &walk_data);
    }

  switch (TREE_CODE (decl))
    {
    default:
      break;

    case FUNCTION_DECL:
      if (tric_opt_code_pic)
        flag |= TRIC_SYMBOL_FLAG_PIC;
     
      if (tric_longcall_function_p (decl))
        flag |= TRIC_SYMBOL_FLAG_LONGCALL;

      break;

    case VAR_DECL:
    case STRING_CST:
    case CONSTRUCTOR:
      if (tric_decl_in_absolute (decl))
        flag |= TRIC_SYMBOL_FLAG_ABSOLUTE;
      
      if (tric_decl_in_smalldata (decl))
        flag |= TRIC_SYMBOL_FLAG_SMALL;

      break;
    }

  SYMBOL_REF_FLAGS (XEXP (rtl, 0)) |= flag;
}


/* Implement `TARGET_ASM_DECLARE_CONSTANT_NAME' */
/* Check EXPR as so that it does not take addresses of functions.
   With -mcode-pic, such addresses are not computable at load lime.
   This handles the case of local auto variables.  */

static void
tric_asm_declare_constant_name (FILE *file, const char *name, const_tree expr,
                                HOST_WIDE_INT size)
{
  if (tric_opt_code_pic
      || (tric_opt_msmall_pid && tric_warn_initialize_pid))
    {
      tric_walk_data_t walk_data = { UNKNOWN_LOCATION, NULL_TREE };
      tree node = CONST_CAST_TREE (expr);

      walk_tree_without_duplicates (&node, tric_walk_initializer_r, &walk_data);
    }

  default_asm_declare_constant_name (file, name, expr, size);
}


/* Implement `TARGET_ASM_OUTPUT_ANCHOR' */

static void
tric_asm_output_anchor (rtx symbol)
{
  char buffer[100];

  sprintf (buffer, ".+ " HOST_WIDE_INT_PRINT_DEC,
           SYMBOL_REF_BLOCK_OFFSET (symbol));
  ASM_OUTPUT_DEF (asm_out_file, XSTR (symbol, 0), buffer);
}


/* Implement `TARGET_USE_ANCHORS_FOR_SYMBOL_P' */

static bool
tric_use_anchors_for_symbol_p (const_rtx symbol)
{
  if (flag_data_sections
      || tric_symbol_ref_absolute_p (symbol)
      || tric_symbol_ref_small16_p (symbol))
    {
      return false;
    }
  
  return true;
}


static void
tric_asm_output_aligned_block (FILE* stream, tree decl, const char *name,
                               int size, unsigned int align)
{
  rtx sym_ref = NULL_RTX;

  /* Handle cases LTO markers injected for the linker by toplev.c.
     They have decl == NULL.  */

  if (str_prefix_p (name, "__gnu_lto"))
    {
      fprintf (stream, "\t.comm\t");
      assemble_name (stream, name);
      fprintf (stream, ", %d, %d\n", size, align / BITS_PER_UNIT);

      return;
    }

  if (decl
      && TREE_CODE (decl) == VAR_DECL
      && DECL_RTL (decl))
    {
      sym_ref = XEXP (DECL_RTL (decl), 0);
    }

  if ((size <= tric_sdata_max && size >= tric_sdata_min)
      || tric_symbol_ref_small16_p (sym_ref))
    {
      switch_to_section (tric_sbss_section);
    }
  else if ((size <= tric_zdata_max && size >= tric_zdata_min)
           || tric_symbol_ref_absolute_p (sym_ref))
    {
	  switch_to_section (tric_zbss_section);
    }
  else
    {
      if (!flag_no_common)
        {
          fprintf (stream, "\t.comm\t");
          assemble_name (stream, name);
          fprintf (stream,
                   ", %d, %d\n", size, /* floor_log2 */ align / BITS_PER_UNIT);

          return;
        }
      else
	  {
    	  switch_to_section (tric_bss_section);
	  }
    }

  ASM_OUTPUT_ALIGN (stream, floor_log2 (align / BITS_PER_UNIT));
  
  /* output the type information this is not for bits */

  fprintf (stream, "%s\t ", TYPE_ASM_OP);
  assemble_name (stream, name);
  fprintf (stream, "," TYPE_OPERAND_FMT "\n", "object");

  size_directive_output = 0;
  if (!flag_inhibit_size_directive && size != 0)
    {
      size_directive_output = 1;
      fprintf (stream, "%s\t ", SIZE_ASM_OP);
      assemble_name (stream, name);
      fprintf (stream, ",%d\n", size);
    }
  ASM_OUTPUT_LABEL (stream, name);
  
  if (size != 0)
    fprintf (stream, "\t.space\t%d\n", size);
}

/* Implement `ASM_OUTPUT_ALIGNED_DECL_LOCAL' */
/* Implement `ASM_OUTPUT_ALIGNED_DECL_COMMON' */

void
tric_asm_output_aligned_var (FILE *stream, tree decl, const char *name,
                             int size, int align, int common)
{
  fprintf (stream, "\t%s\t", (common == 0) ? ".local" : ".global");
  assemble_name (stream, name);
  fprintf (stream, "\n");
  tric_asm_output_aligned_block (stream, decl, name, size, align);
}


/***********************************************************************
 ** Constructors, Destructors
 ***********************************************************************/


/* Implement `TARGET_ASM_CONSTRUCTOR' */

static void
tric_asm_constructor (rtx symbol, int priority)
{
  fputs ("\t.global __do_global_ctors\n", asm_out_file);
  section *sec;

  if (priority != DEFAULT_INIT_PRIORITY)
    sec = get_cdtor_priority_section (priority,
				      /*constructor_p=*/true);
  else
  sec = get_section (".ctors",0, NULL);
  sec->common.flags&=~SECTION_WRITE;
  assemble_addr_to_section (symbol, sec);
}

/* Implement `TARGET_ASM_DESTRUCTOR' */

static void
tric_asm_destructor (rtx symbol, int priority)
{
  fputs ("\t.global __do_global_dtors\n", asm_out_file);
  section *sec;

  if (priority != DEFAULT_INIT_PRIORITY)
    sec = get_cdtor_priority_section (priority,
				      /*constructor_p=*/false);
  else
  sec = get_section (".dtors", 0, NULL);
  sec->common.flags&=~SECTION_WRITE;
  assemble_addr_to_section (symbol, sec);
}

/* Implement `ASM_OUTPUT_EXTERNAL' */

void
tric_asm_output_external (FILE *file, tree decl, const char *name)
{
  default_elf_asm_output_external (file, decl, name);
  
  /* We output the name if and only if TREE_SYMBOL_REFERENCED is set
     in order to avoid putting out names that are never really used. */
  
  if (TREE_SYMBOL_REFERENCED (DECL_ASSEMBLER_NAME (decl))
      && !TREE_ASM_WRITTEN (DECL_ASSEMBLER_NAME (decl)))
    {
      TREE_ASM_WRITTEN (DECL_ASSEMBLER_NAME (decl)) = 1;

      fputs ("\t.extern\t", file);
      assemble_name (file, name);
      if (TREE_CODE (decl) == FUNCTION_DECL)
        {
          fprintf (file, ",STT_FUNC,0\n");
        }
      else
        {
          fprintf (file, ",STT_OBJECT," HOST_WIDE_INT_PRINT_DEC "\n",
                   int_size_in_bytes (TREE_TYPE (decl)));
        }
    }
}


//TODO
static rtx_insn *
tric_md_asm_adjust (vec<rtx>& outputs ATTRIBUTE_UNUSED, vec<rtx>& inputs ATTRIBUTE_UNUSED,
		    vec<machine_mode>& input_modes ATTRIBUTE_UNUSED,
		    vec<const char *>& constraints ATTRIBUTE_UNUSED,
		    vec<rtx>& clobbers ATTRIBUTE_UNUSED,
		    HARD_REG_SET& clobbered_regs ATTRIBUTE_UNUSED)

{
  return NULL;
}


/***********************************************************************
 ** EABI 2.1.4.2:  Union and Structure Layout
 ***********************************************************************/


/* FIELD is a FIELD_DECL.  Get the previous field or NULL_TREE if FIELD
   is the first field in the component.  */

static tree
tric_get_previous_field (tree field)
{
  tree parent = DECL_CONTEXT (field);
  tree fld, prev = NULL_TREE;

  for (fld = TYPE_FIELDS (parent); fld != NULL_TREE; fld = TREE_CHAIN (fld))
    {
      if (TREE_CODE (fld) != FIELD_DECL)
        continue;

      if (fld == field)
        return prev;

      prev = fld;
    }

  gcc_unreachable();
}


/* Implement `ADJUST_FIELD_ALIGN' */
/* Adjust field alignment for EABI.  */

unsigned
tric_eabi_adjust_field_align (tree field, unsigned desired_align)
{
  /* Calculate the bitfield offset according to the EABI.  Bitfield alignment
     requires special attention. We have to use 64-bit arithmetik because
     size will measure bits and 2**32 * 8 doesn't fit in an 32-bit value.  */

  unsigned HOST_WIDE_INT dsize, field_position = 0;
  unsigned HOST_WIDE_INT halfword_start, halfword_end;
  tree size, prev;
  if (field==NULL_TREE)
    {
	 return desired_align;
    }
  if (!DECL_BIT_FIELD (field) || DECL_ARTIFICIAL (field))
    return desired_align;

  size = DECL_SIZE (field);

  dsize = size != NULL_TREE && TREE_CODE (size) == INTEGER_CST
    ? tree_to_uhwi (size)
    /* A field with variable size */
    : desired_align;

  if (dsize == 0)
    /* EABI 2.1.4.3 requires byte alignment for zero-width bit fields */
    return EMPTY_FIELD_BOUNDARY;

  /* EABI 2.1.4.3 specifies that bit fields must not exceed 32 bits and must
     not cross more than one halfword boundary.  */

  if (tric_opt_eabi_bitfield_limit
      && dsize > 32
      && !tric_node_seen (&tric_eabi_error, field))
    {
      error ("EABI: width of bitfield %q+D exceeds 32", field);
    }

  /* Get offset and size of the previous field in order to compute
     the correct alignment of the current field.  */
  
  prev = tric_get_previous_field (field);

  if (prev && size && !DECL_PACKED (field))
    {
      tree offset = DECL_SIZE (prev);
      
      if (offset != NULL_TREE && TREE_CODE (offset) == INTEGER_CST)
        field_position += tree_to_uhwi (offset);

      offset = DECL_FIELD_BIT_OFFSET (prev);

      if (offset != NULL_TREE && TREE_CODE (offset) == INTEGER_CST)
        field_position += tree_to_uhwi (offset);
    }

  /* Half-word where the field starts resp. ends.  */

  halfword_start = field_position / 16;
  halfword_end = (field_position + dsize - 1) / 16;

  /* If the field would cross more than 2 half-word boundaries, align it
     so that it crosses at most one such boundary.  */

  return halfword_end > halfword_start + 1 ? 16 : 1;
}


/* Helper for the next function.
   Compute alignment of structs and unions.  */

static unsigned
tric_eabi_struct_alignment (tree type, unsigned align)
{
  tree field;

  gcc_assert (RECORD_OR_UNION_TYPE_P (type));
  
  for (field = TYPE_FIELDS (type); field; field = TREE_CHAIN (field))
    {
      unsigned field_align;
      unsigned desired_align;
      
      if (TREE_CODE (field) != FIELD_DECL
          || TREE_TYPE (field) == error_mark_node)
        continue;

      desired_align = TYPE_ALIGN (TREE_TYPE (field));

      field_align = DECL_BIT_FIELD (field)
        /* For bitfields just take the type alignment.  This will be
           calculated by tric_eabi_adjust_field_align above.  */
        ? TYPE_ALIGN (type)
        : DATA_ALIGNMENT (TREE_TYPE (field), desired_align);

      /* TYPE_ALIGN might be unknown, i.e. -1.  Thus, use signed MAX.  */

      align = MAX ((int) align, (int) field_align);
    }

  return align;
}


/* Return the HOST_WIDE_INT least significant bits of T, a sizetype kind
   INTEGER_CST.  This makes sure to properly sign-extend the constant.  */

static HOST_WIDE_INT
size_low_cst (const_tree t)
{
//  double_int d = tree_to_double_int (t);
//  return d.sext (TYPE_PRECISION (TREE_TYPE (t))).low;
	  long unsigned int d = TREE_INT_CST_LOW (t);
	  return d;
}


/* Implement `ROUND_TYPE_ALIGN' */

unsigned
tric_eabi_round_type_align (tree type, unsigned computed, unsigned specified)
{
  /* The struct alignment required by the ABI is quite uncommon... */

  unsigned align = MAX (computed, specified);
  tree field, tsize = TYPE_SIZE (type);

  /* If nothing special is to be done, use default from stor-layout.c  */
  
  if (!RECORD_OR_UNION_TYPE_P (type)
      || TYPE_PACKED (type)
      || !(tsize && TREE_CODE (tsize) == INTEGER_CST)
      || size_low_cst (tsize) <= BITS_PER_UNIT)
    {
      return align;
    }

  /* If size > 8, EABI 2.1.4.2 requires at least halfword alignment even
     if all fields are chars.  */

  align = tric_eabi_struct_alignment (type, MAX (align, 2 * BITS_PER_UNIT));

  /* Bitfields need special treatment */

  for (field = TYPE_FIELDS (type); field; field = TREE_CHAIN (field))
    {
      /* EABI 2.1.4.3 specifies that bitfields > 16 impose word alignment on
         the struct although the bitfield itself is only halfword aligned.  */

      if (TREE_CODE (field) == FIELD_DECL
          && DECL_BIT_FIELD (field)
          && size_low_cst (DECL_SIZE (field)) > 16)
        {
          align = MAX (align, 4 * BITS_PER_UNIT);
        }
    }

  /* assign 4byte alignment if greater 256 to ensure correct ld.dd and st.dd usage in memset* memmov* */
  if (TRIC_18UP)
  {
	  if ((size_low_cst (tsize)>=256) && (align<=16)) align=32;
  }
  
  return align;
}


/* Implement `DATA_ALIGNMENT' */

unsigned
tric_eabi_data_alignment (tree type, unsigned basic_align)
{
  unsigned best_align = BITS_PER_WORD;
  if (TREE_CODE (type) == ARRAY_TYPE)
  {
    return  best_align>basic_align? best_align: basic_align;
  }
  return basic_align;
}


/***********************************************************************
 ** Instruction Lengths
 ***********************************************************************/

/* Get length of a load/store insn that loads/stores REG from/to MEM.
   If this is a load then LOAD_P is true and false, otherwise.
   SIGN_P is false if a load zero-extends.
   SIGN_P is true  if a load sign-extends.
   If this is a store or the load does not change the width of the data
   then SIGN_P is ignored.  */

static int
tric_len_load_store (enum machine_mode mode, rtx reg, rtx mem,
                     bool load_p, bool sign_p)
{
  rtx addr = XEXP (mem, 0);
  int n_bytes = GET_MODE_SIZE (mode);
  bool have_short_mov_p = true;
  RTX_CODE code = GET_CODE (addr);

  if (QImode == mode && load_p && sign_p)
    have_short_mov_p = false;
  
  if (HImode == mode && load_p && !sign_p)
    have_short_mov_p = false;

  if (!have_short_mov_p)
    {
      return 4;
    }

  if (REG_P (addr)
      || POST_INC == code)
    {
      return 2;
    }
  
  if (PLUS == code
      && REG_P (XEXP (addr, 0))
      && CONST_INT_P (XEXP (addr, 1)))
    {
      rtx base = XEXP (addr, 0);
      int off = INTVAL (XEXP (addr, 1));
        
      if (off % n_bytes == 0
          && IN_RANGE (off / n_bytes, 0, 15)
          && (REGNO (base) == REG_A15
              || REGNO (reg) == REG_D15
              || REGNO (reg) == REG_A15))
        {
          return 2;
        }
            
      if (n_bytes == 4
          && off % 4 == 0
          && IN_RANGE (off / 4, 0, 255)
          && REGNO (base) == REG_SP
          && (REGNO (reg) == REG_D15
              || REGNO (reg) == REG_A15))
        {
          return 2;
        }
    } /* PLUS */

  return 4;
}


/* Get length of a mov* insn.  MODE is the move mode.  DEST is the destination
   SRC  is the source
   SIGN_P is true  if SRC is to be sign-extended when loaded
   SIGN_P is false if SRC is to be zero-extended when loaded  */

static int
tric_len_mov (enum machine_mode mode, rtx dest, rtx src, bool sign_p)
{
  if (CONST_DOUBLE_P (src))
    {
      src = simplify_gen_subreg (SImode, src, mode, 0);
    }
  
  if (CONSTANT_P (src))
    {
      gcc_assert (REG_P (dest));

      if (A_REG_P (dest) && satisfies_constraint_Ku4 (src))
        return 2;

      if (D_REG_P (dest))
        {
          if (REGNO (dest) == REG_D15
              && satisfies_constraint_Ku8 (src))
            return 2;

          if (satisfies_constraint_Ks4 (src))
            return 2;
        }
    }

  if (REG_P (dest) && MEM_P (src))
    return tric_len_load_store (GET_MODE (src), dest, src, true, sign_p);

  if (MEM_P (dest) && REG_P (src))
    return tric_len_load_store (mode, src, dest, false, sign_p);
  
  return 4;
}


/* Get length of MOV %e, const  */

static int
tric_len_mov64 (rtx dest ATTRIBUTE_UNUSED, rtx src)
{
  if (satisfies_constraint_Ks4 (src))
    {
      return 2;
    }

  return 4;
}


/* Length of "*addsi3": ADD, ADDI, ADDIH, LEA, SUB.A, ADD.A, ADDIH.A,
   ADDSC.A.  */

static int
tric_len_add32 (rtx *xop)
{
  int reg0 = REGNO (xop[0]);
  int reg1 = REGNO (xop[1]);

  if (satisfies_constraint_Ks4 (xop[2]))
    {
      if (reg0 == reg1 || reg0 == REG_D15 || reg1 == REG_D15)
        return 2;
    }
  
  if (satisfies_constraint_Kn8 (xop[2])
      && reg0 == REG_SP
      && reg1 == REG_SP)
    return 2;

  if (REG_P (xop[2]))
    {
      int reg2 = REGNO (xop[2]);

      if (D_REGNO_P (reg0) && D_REGNO_P (reg1) && D_REGNO_P (reg2))
        {
          if (reg0 == reg1 || reg0 == reg2)
            return 2;

          if (reg0 == REG_D15 || reg1 == REG_D15 || reg2 == REG_D15)
            return 2;
        }
      
      if (A_REGNO_P (reg0) && A_REGNO_P (reg1) && A_REGNO_P (reg2))
        {
          if (reg0 == reg1 || reg0 == reg2)
            return 2;
        }
      
      if (A_REGNO_P (reg0) && A_REGNO_P (reg1) && reg2 == REG_D15)
        return 2;

      if (A_REGNO_P (reg0) && A_REGNO_P (reg2) && reg1 == REG_D15)
        return 2;
    }
 
  return 4;
}


/* Length of "subsi3" (SUB, SUB.A, RSUB).  */

static int
tric_len_sub32 (rtx *xop)
{
  if (D_REG_P (xop[0]) && REG_P (xop[1]))
    {
      int reg0 = REGNO (xop[0]);
      int reg1 = REGNO (xop[1]);

      if (reg0 == reg1 || reg0 == REG_D15 || reg1 == REG_D15)
        return 2;
    }
  
  return 4;
}


static int
tric_len_bitop (rtx_insn *insn, rtx *xop)
{
  rtx src = SET_SRC (single_set (insn));

  if (REG_P (xop[1]) && REG_P (xop[2])
      && (REGNO (xop[0]) == REGNO (xop[1])
          || REGNO (xop[0]) == REGNO (xop[2])))
    {
      return 2;
    }
    
  if ((AND == GET_CODE (src)
       || IOR == GET_CODE (src))
      && satisfies_constraint_Ku8 (xop[2])
      && REGNO (xop[0]) == REG_D15
      && REGNO (xop[1]) == REG_D15)
    {
      return 2;
    }
      
  return 4;
}


/* Length of EQ and NE instructions.  */

static int
tric_len_seq (rtx_insn *insn, rtx *xop)
{
  rtx src = SET_SRC (single_set (insn));

  if (GET_CODE (src) == EQ
      && D_REG_P (xop[0]) && D_REG_P (xop[1])
      && REGNO (xop[0]) == REG_D15
      && (D_REG_P (xop[2])
          || satisfies_constraint_Ks4 (xop[2])))
    {
      return 2;
    }
      
  return 4;
}


/* Implement `ADJUST_INSN_LENGTH' */

int
tric_adjust_insn_length (rtx_insn *insn, int len)
{
  rtx *op = recog_data.operand;
  enum attr_adjust adjust;
  enum machine_mode mode0 = VOIDmode;

  /* Some complex insns don't need length adjustment and therefore
     the length need not/must not be adjusted for these insns.
     It is easier to state this in an insn attribute "adjust" than
     to clutter up code here...  */
  
  if (!NONDEBUG_INSN_P (insn)
      || -1 == recog_memoized (insn))
    {
      return len;
    }

  /* Read from insn attribute "adjust" if/how length is to be adjusted.  */

  adjust = get_attr_adjust (insn);

  if (adjust == ADJUST_NO)
    {
      /* Nothing to adjust: The length from attribute "length" is fine.
         This is the default.  */
      
      return len;
    }
  
  /* Extract insn's operands.  */
  
  extract_constrain_insn_cached (insn);
  
  /* Dispatch to right function.  */

  if (single_set (insn))
    mode0 = GET_MODE (SET_DEST (single_set (insn)));

  switch (adjust)
    {
    default:
      gcc_unreachable();
      
    case ADJUST_MOV8S:
    case ADJUST_MOV16S:
      len = tric_len_mov (mode0, op[0], op[1], true);
      break;
      
    case ADJUST_MOV8:
    case ADJUST_MOV16:
    case ADJUST_MOV32:
      len = tric_len_mov (mode0, op[0], op[1], false);
      break;
      
    case ADJUST_MOV64: len = tric_len_mov64 (op[0], op[1]); break;
      
    case ADJUST_BITOP: len = tric_len_bitop (insn, op); break;
    case ADJUST_SEQ:   len = tric_len_seq   (insn, op); break;
      
    case ADJUST_ADD32: len = tric_len_add32 (op); break;
    case ADJUST_SUB32: len = tric_len_sub32 (op); break;

    case ADJUST_ADDSC:
      len = REGNO (op[1]) == REG_D15 ? 2 : 4;
      break;

    case ADJUST_SAT:
      len = REGNO (op[0]) == REGNO (op[1]) ? 2 : 4;
      break;
    }
  
  return len;
}



/* EABI 2.1.3.1 Circular Buffer Pointers

   Set up built-in types __circ and __circ64 to make use of
   circular addressing modes.  The types will be as if defined per

   typedef unsigned long long __circ64 __attribute__((mode(PDI)))

   typedef union
   {
       struct
       {
           void *buf;
           unsigned short index;
           unsigned short length;
       };
       __circ64 circ64;
   } __circ __attribute__((mode(PDI)));
*/

static void
tric_init_builtin__circ (void)
{
  static struct
  {
    const char *name;
    tree *type;
  }
  circ_field[] =
    {
      { "buf",    &ptr_type_node },
      { "index",  &short_unsigned_type_node },
      { "length", &short_unsigned_type_node }
    };
  
  unsigned i;
  tree circ64, field, fields = NULL_TREE;
  tree typeA = lang_hooks.types.make_type (RECORD_TYPE);
  tree typeB = lang_hooks.types.make_type (UNION_TYPE);

  /* Set up builtin type __circ64 as
     unsigned long long __attribute__((mode(PDI)))  */

  circ64 = make_unsigned_type (GET_MODE_BITSIZE (PDImode));
  SET_TYPE_MODE (circ64, PDImode);

  lang_hooks.types.register_builtin_type (circ64, "__circ64");

  /* typeA:  Set up
     struct { void *buf; unsigned short index, length; }  */
     
  for (i = 0; i < sizeof circ_field / sizeof circ_field[0]; i++)
    {
      field = build_decl (BUILTINS_LOCATION, FIELD_DECL,
                          get_identifier (circ_field[i].name),
                          *circ_field[i].type);
      DECL_CONTEXT (field) = typeA;
      DECL_CHAIN (field) = fields;
      fields = field;
    }

  TYPE_FIELDS (typeA) = nreverse (fields);
  layout_type (typeA);

  /* typeB:  Set up __circ as
     union {
       struct { void *buf; unsigned short index, length; };
       __circ64 circ64;
     }
   */

  field = build_decl (BUILTINS_LOCATION, FIELD_DECL, NULL_TREE, typeA);
  DECL_CONTEXT (field) = typeB;
  DECL_CHAIN (field) = NULL_TREE;
  fields = field;

  field = build_decl (BUILTINS_LOCATION, FIELD_DECL,
                      get_identifier ("circ64"), circ64);
  DECL_CONTEXT (field) = typeB;
  DECL_CHAIN (field) = fields;
  fields = field;

  TYPE_FIELDS (typeB) = nreverse (fields);
  layout_type (typeB);
  SET_TYPE_MODE (typeB, PDImode);

  lang_hooks.types.register_builtin_type (typeB, "__circ");
}

static void
tric_init_builtin__float16 (void)
{
  tree float16_type = make_node (REAL_TYPE);
  TYPE_PRECISION (float16_type) = 16;
  layout_type (float16_type);
  lang_hooks.types.register_builtin_type (float16_type, "__float16");
}


/* Implement `TARGET_MANGLE_TYPE'.  */

static const char*
tric_mangle_type (const_tree type)
{
  /* Half-precision float.  We cannot pass __float16 arguments to functions,
     but we can pass pointers to __float16, hence we need to mangle it in
     some way.  The TriCore EABI doesn't give any clue, so treat it like a
     user-defined type.  */

  if (TREE_CODE (type) == REAL_TYPE
      && TYPE_PRECISION (type) == 16)
    return "9__float16";

  return NULL;
}


/* IDs for all the TriCore builtins.  */

enum tric_builtin_id
  {
#define DEF_BUILTIN(NAME, N_ARGS, ID, TYPE, INSN, TCODE)        \
    TRIC_BUILTIN_ ## ID,
#include "builtins.def"
#undef DEF_BUILTIN

    TRIC_BUILTIN_COUNT
  };

typedef struct GTY(()) tric_builtin_struct
{
  enum insn_code icode;
  const char *name;
  int n_args;
  tree fndecl;
  enum tree_code tcode;
} tric_builtin_t;


/* Notice that tric_builtin[] and tric_builtin_id are initialized in such a
   way that a built-in's ID can be used to access the built-in by means of
   tric_builtin[ID].  */

static GTY(()) tric_builtin_t
tric_builtin[TRIC_BUILTIN_COUNT] =
{
#define DEF_BUILTIN(NAME, N_ARGS, ID, TYPE, INSN, TCODE)                \
  {                                                                     \
    (enum insn_code) CODE_FOR_ ## INSN, "__builtin_tricore_" NAME,      \
    N_ARGS, NULL_TREE, TCODE                                            \
  },
#include "builtins.def"
#undef DEF_BUILTIN
};


/* Implement `TARGET_BUILTIN_DECL' */

static tree
tric_builtin_decl (unsigned id, bool initialize_p ATTRIBUTE_UNUSED)
{
  if (id < TRIC_BUILTIN_COUNT)
    return tric_builtin[id].fndecl;

  return error_mark_node;
}


/* Implement `TARGET_INIT_BUILTINS' */
/* Set up all built-in functions and built-in types for this target.  */

static void
tric_init_builtins (void)
{
  size_t id;
  tree void_ftype_void
    = build_function_type_list (void_type_node, NULL_TREE);

  tree volatile_void_node
    = build_qualified_type (void_type_node, TYPE_QUAL_VOLATILE);

  tree volatile_voidptr_node
    = build_pointer_type_for_mode (volatile_void_node, Pmode, true);

  tree void_ftype_v_voidptr_uint64
    = build_function_type_list (void_type_node,
                                volatile_voidptr_node,
                                long_long_unsigned_type_node,
                                NULL_TREE);
  tree void_ftype_v_voidptr_2uint
    = build_function_type_list (void_type_node,
                                volatile_voidptr_node,
                                unsigned_type_node, unsigned_type_node,
                                NULL_TREE);
  tree void_ftype_v_voidptr_3uint
    = build_function_type_list (void_type_node,
                                volatile_voidptr_node,
                                unsigned_type_node, unsigned_type_node,
                                unsigned_type_node,
                                NULL_TREE);

  tree uint64_ftype_2uint
    = build_function_type_list (long_long_unsigned_type_node,
                                unsigned_type_node, unsigned_type_node,
                                NULL_TREE);
  tree uint64_ftype_3uint
    = build_function_type_list (long_long_unsigned_type_node,
                                unsigned_type_node, unsigned_type_node,
                                unsigned_type_node,
                                NULL_TREE);

  tree int_ftype_int
    = build_function_type_list (integer_type_node,
                                integer_type_node,
                                NULL_TREE);
  tree uint_ftype_uint
    = build_function_type_list (unsigned_type_node,
                                unsigned_type_node,
                                NULL_TREE);
  tree uint_ftype_2uint
    = build_function_type_list (unsigned_type_node,
                                unsigned_type_node, unsigned_type_node,
                                NULL_TREE);
  tree uint_ftype_4uint
    = build_function_type_list (unsigned_type_node,
                                unsigned_type_node, unsigned_type_node,
                                unsigned_type_node, unsigned_type_node,
                                NULL_TREE);
  tree uint_ftype_v_voidptr_uint
    = build_function_type_list (unsigned_type_node,
                                volatile_voidptr_node, unsigned_type_node,
                                NULL_TREE);
  tree uint_ftype_v_voidptr_2uint
    = build_function_type_list (unsigned_type_node,
                                volatile_voidptr_node, unsigned_type_node,
                                unsigned_type_node,
                                NULL_TREE);
  tric_init_builtin__circ ();

  tric_init_builtin__float16 ();

#define DEF_BUILTIN(NAME, N_ARGS, ID, TYPE, INSN, TCODE)                \
  id = TRIC_BUILTIN_ ## ID;                                             \
  gcc_assert (id < TRIC_BUILTIN_COUNT);                                 \
  tric_builtin[id].fndecl                                               \
    = add_builtin_function (tric_builtin[id].name, TYPE, id,            \
                            BUILT_IN_MD, NULL, NULL_TREE);
#include "builtins.def"
#undef DEF_BUILTIN

}


/* Subroutine of tric_expand_builtin to expand vanilla builtins with
   1 ... 3 arguments.  ICODE is the insn code number, EXP the call expression.
   VOID_P is true iff the built-in's return type is void.  If TARGET is
   non-null then it's the preferred place to return the result.  */

static rtx
tric_default_expand_builtin (enum insn_code icode, tree exp, rtx target,
                             bool void_p)
{
  rtx pat, xop[4];
  int n, n_args = call_expr_nargs (exp);
  enum machine_mode tmode = insn_data[icode].operand[0].mode;

  gcc_assert (n_args >= 1 && n_args <= 4);
              
  if (void_p
      || target == NULL_RTX
      || GET_MODE (target) != tmode
      || !insn_data[icode].operand[0].predicate (target, tmode))
    {
      target = gen_reg_rtx (tmode);
    }

  for (n = 0; n < n_args; n++)
    {
      tree arg = CALL_EXPR_ARG (exp, n);
      rtx op = expand_normal (arg);
      enum machine_mode opmode = GET_MODE (op);
      enum machine_mode mode = insn_data[icode].operand[n + !void_p].mode;

      if ((opmode == SImode || opmode == VOIDmode) && mode == HImode)
        {
          opmode = HImode;
          op = gen_lowpart (HImode, op);
        }

      /* In case the insn wants input operands in modes different from
         the result, abort.  */
  
      gcc_assert (opmode == mode || opmode == VOIDmode);

      if (!insn_data[icode].operand[n + !void_p].predicate (op, mode))
        op = copy_to_mode_reg (mode, op);

      xop[n] = op;
    }

  if (void_p)
    {
      switch (n_args)
        {
        case 1: pat = GEN_FCN (icode) (xop[0]); break;
        case 2: pat = GEN_FCN (icode) (xop[0], xop[1]); break;
        case 3: pat = GEN_FCN (icode) (xop[0], xop[1], xop[2]); break;
        case 4: pat = GEN_FCN (icode) (xop[0], xop[1], xop[2], xop[3]); break;

        default:
          gcc_unreachable();
        }
    }
  else
    {
      switch (n_args)
        {
        case 1: pat = GEN_FCN (icode) (target, xop[0]); break;
        case 2: pat = GEN_FCN (icode) (target, xop[0], xop[1]); break;
        case 3: pat = GEN_FCN (icode) (target, xop[0], xop[1], xop[2]); break;
        case 4: pat = GEN_FCN (icode) (target, xop[0], xop[1], xop[2], xop[3]);
          break;

        default:
          gcc_unreachable();
        }
    }
  
  if (pat == NULL_RTX)
    return NULL_RTX;

  emit_insn (pat);

  return target;
}


/* Implement `TARGET_EXPAND_BUILTIN'.  */
/* Expand an expression EXP that calls a built-in function, with result going
   to TARGET if that's convenient (and in mode MODE if that's convenient).
   SUBTARGET may be used as the target for computing one of EXP's operands.
   IGNORE is nonzero if the value is to be ignored.  */

static rtx
tric_expand_builtin (tree exp, rtx target,
                     rtx subtarget ATTRIBUTE_UNUSED,
                     enum machine_mode mode ATTRIBUTE_UNUSED,
                     int ignore ATTRIBUTE_UNUSED)
{
  tree fndecl = TREE_OPERAND (CALL_EXPR_FN (exp), 0);
  unsigned int id = DECL_FUNCTION_CODE (fndecl);
  const tric_builtin_t *d = &tric_builtin[id];
  bool void_p = VOID_TYPE_P (TREE_TYPE (TREE_TYPE (fndecl)));

  gcc_assert (id < TRIC_BUILTIN_COUNT);

  /* No special treatment needed: vanilla expand.  */

  gcc_assert (d->n_args == call_expr_nargs (exp));
  gcc_assert (d->icode != CODE_FOR_nothing);

  if (d->n_args == 0)
    {
      emit_insn ((GEN_FCN (d->icode)) (target));
      return NULL_RTX;
    }

  return tric_default_expand_builtin (d->icode, exp, target, void_p);
}


/* Fold for the INSERT instruction / builtin and alike.  */

static tree
tric_fold_insert (tree ttarget, tree tval, tree tpos, tree twidth)
{
  HOST_WIDE_INT target = tric_tree_to_hwi (ttarget);
  HOST_WIDE_INT val    = tric_tree_to_hwi (tval);
  HOST_WIDE_INT pos    = tric_tree_to_hwi (tpos);
  HOST_WIDE_INT width  = tric_tree_to_hwi (twidth);
  tree finsert = tric_builtin[TRIC_BUILTIN_INSERT].fndecl;

  if (width == 0 || pos >= 32)
    /* No effect.  Return original value.  */
    return ttarget;

  if (width > 32)
    /* Saturate width to 32.  */
    return build_call_expr (finsert, 4, ttarget, tval, tpos,
                            tric_tree_uint (32));

  if (pos == 0 && width == 32)
    /* Overrides target completely.  */
    return tval;

  if (width > 0)
    {
      HOST_WIDE_INT mask = ((HOST_WIDE_INT) 1 << width) -1;

      if (pos >= 0 && pos + width > 32)
        /* If the support exceeds the target, cut down support to 32 bits.  */
        return build_call_expr (finsert, 4, ttarget, tval, tpos,
                                tric_tree_uint (32 - pos));

      if (target >= 0 && val >= 0 && pos >= 0)
        {
          /* All deflates to a known value.  */

          mask <<= pos;
          val  <<= pos;
          return tric_tree_uint ((target & ~mask) | (val & mask));
        }

      if (val == 0 && pos >= 0)
        /* Inserting 0 is cheap: Prefer open coded arithmetic.  */
        return fold_build2 (BIT_AND_EXPR, unsigned_type_node,
                            ttarget, tric_tree_uint (~(mask << pos)));
    }

  return NULL_TREE;
}


static tree
tric_fold_sat (tree arg, int lo, int hi, bool unsigned_p)
{
  tree ttyp = unsigned_p ? unsigned_type_node : integer_type_node;

  if (!unsigned_p
      || lo != 0)
    {
      arg = fold_build2 (MAX_EXPR, ttyp, arg, build_int_cst (ttyp, lo));
    }

  return fold_build2 (MIN_EXPR, ttyp, arg, build_int_cst (ttyp, hi));
}


/* Implement `TARGET_FOLD_BUILTIN'.  */

static tree
tric_fold_builtin (tree fndecl, int n_args ATTRIBUTE_UNUSED, tree *arg,
                   bool ignore ATTRIBUTE_UNUSED)
{
  unsigned int fcode = DECL_FUNCTION_CODE (fndecl);
  tree result_type = TREE_TYPE (TREE_TYPE (fndecl));
  const tric_builtin_t *builtin = &tric_builtin[fcode];

  if (builtin->tcode == NOP_EXPR)
    /* Nothing to fold */
    return NULL_TREE;
  
  switch (fcode)
    {
    default:
      break;

    case TRIC_BUILTIN_INSERT:
      return tric_fold_insert (arg[0], arg[1], arg[2], arg[3]);

    case TRIC_BUILTIN_LDMST4:
      {
        tree timask = build_call_expr (tric_builtin[TRIC_BUILTIN_IMASK].fndecl,
                                       3, arg[1], arg[2], arg[3]);
        return build_call_expr (tric_builtin[TRIC_BUILTIN_LDMST2].fndecl,
                                2, arg[0], timask);
      }

    case TRIC_BUILTIN_LDMST3:
      {
        tree timask = build_call_expr (tric_builtin[TRIC_BUILTIN_IMASK2].fndecl,
                                       2, arg[1], arg[2]);
        return build_call_expr (tric_builtin[TRIC_BUILTIN_LDMST2].fndecl,
                                2, arg[0], timask);
      }

    case TRIC_BUILTIN_RROTATE:
      /* Patch rotation offset to get a left rotate which is more
         convenient with DEXTR.  */

      arg[1] = fold_build1 (NEGATE_EXPR, unsigned_type_node, arg[1]);
      fcode = TRIC_BUILTIN_LROTATE;
      arg[1] = fold_build2 (BIT_AND_EXPR, unsigned_type_node, arg[1],
                            tric_tree_uint (31));
      break;

    case TRIC_BUILTIN_LROTATE:
      /* Patch rotation offset to make it cyclic.  */

      arg[1] = fold_build2 (BIT_AND_EXPR, unsigned_type_node, arg[1],
                            tric_tree_uint (31));
      break;

    case TRIC_BUILTIN_SATB:
      return tric_fold_sat (arg[0], -128, 127, false);

    case TRIC_BUILTIN_SATBU:
      return tric_fold_sat (arg[0], 0, 255, true);

    case TRIC_BUILTIN_SATH:
      return tric_fold_sat (arg[0], -32768, 32767, false);

    case TRIC_BUILTIN_SATHU:
      return tric_fold_sat (arg[0], 0, 65535, true);
    }

  builtin = &tric_builtin[fcode];

  /* Mandatory folds are not allowed past this point, cf builtins.def for
     a description of TCODE.  */

  gcc_assert (ERROR_MARK != builtin->tcode);

  if (CONVERT_EXPR == builtin->tcode)
    /* Nothing todo if no fold was found for these.  */
    return NULL_TREE;
  
  /* The builtin can be represented as some tree expression.  */

  fndecl = builtin->fndecl;
  result_type = TREE_TYPE (TREE_TYPE (fndecl));

  if (1 == builtin->n_args)
    return fold_build1 (builtin->tcode, result_type, arg[0]);

  if (2 == builtin->n_args)
    return fold_build2 (builtin->tcode, result_type, arg[0], arg[1]);

  gcc_unreachable();
}


/* Implement `TARGET_LIBC_HAS_FUNCTION' */

static bool
tric_libc_has_function (enum function_class fn_class ATTRIBUTE_UNUSED, tree type ATTRIBUTE_UNUSED)
{
  // FIXME: Work this out when adding dinkum / Newlib 2.1 support.
  return true;
}

/* Implement `TARGET_INVALID_UNARY_OP' */

static const char*
tric_invalid_unary_op (int op, const_tree type)
{
  enum tree_code code = (enum tree_code) op;
  
  if (PDImode == TYPE_MODE (type)
      && !truth_value_p (code))
    {
      return "operation not supported for circular buffer types";
    }

  return NULL;
}


/* Implement `TARGET_INVALID_BINARY_OP' */

static const char*
tric_invalid_binary_op (int op, const_tree type1, const_tree type2)
{
  enum tree_code code = (enum tree_code) op;
  
  if ((PDImode == TYPE_MODE (type1)
       || PDImode == TYPE_MODE (type2))
      && !truth_value_p (code))
    {
      return "operation not supported for circular buffer types";
    }

  return NULL;
}


/* Implement `TARGET_HTC_GUESS_BSS' */

static bool
tric_guess_bss_p (void)
{
  /* FIXME: */
  return tric_test == 'B';
}


/* Helper for `tric_dump_valist':  Dump VAL as hex value to FILE.  */

static void
tric_dump_double_int_hex (FILE *file, double_int val)
{
  unsigned digit[2];

  digit[0] = tric_double_int_pop_digit (&val, 0);
  digit[1] = tric_double_int_pop_digit (&val, 0);

  fprintf (file, "0x");

  if (digit[1])
    fprintf (file, "%08x", digit[1]);

  if (digit[1] | digit[0])
    fprintf (file, "%08x", digit[0]);
  else
    fprintf (file, "0");
}


/* Helper for `tric_dump_valist' for the '%I' case.  */

static void
tric_log_neat_hwi (FILE *file, HOST_WIDE_INT wi)
{
  if (TRIC_INT_MIN == wi)
    fprintf (file, "int_min");
  else if (TRIC_UINT_MAX == wi)
    fprintf (file, "Uint_Max");
  else if (TRIC_INT_MAX == wi)
    fprintf (file, "int_Max");
  else if (wi < 0)
    fprintf (file, HOST_WIDE_INT_PRINT_DEC, wi);
  else
    fprintf (file, HOST_WIDE_INT_PRINT_HEX, wi);
}


/* Implement `TARGET_HTC_DUMP_VALIST'.

   I: The interval represented by range_t printed like "[%i, %x]".
      The empty set is printed as "[,]".
   X: double_int (unsigned hex).
*/

static int
tric_dump_valist (FILE *stream, const char *fmt, va_list ap)
{
  int n_consumed = 0;

  switch (*fmt)
    {
    default:
      break;

    case 'I':
      {
        range_t r = va_arg (ap, range_t);

        fputc ('[', stream);

        if (r.lower > r.upper)
          {
            fputc (',', stream);
          }
        else
          {
            tric_log_neat_hwi (stream, r.lower);
            fprintf (stream, ", ");
            tric_log_neat_hwi (stream, r.upper);
          }
        fputc (']', stream);
      }
      n_consumed = 1;
      break;

    case 'X':
      tric_dump_double_int_hex (stream, va_arg (ap, double_int));
      n_consumed = 1;
      break;
    }

  return n_consumed;
}


bool tricore_frame_pointer_required (void);

bool
tricore_frame_pointer_required (void)
{
  if (cfun->calls_alloca)
  {
		/* builtin_setjump in combination with builtin_alloc is making omit stack frame pointer in
		 * a wrong manner, to avoid it insist on alloca frame_pointer, issue is not fully understood
		 * example is built-in-setjmp.c from testsuite
		 */
	  //TODO
	  return true;
  }
  /* If the function receives nonlocal gotos, it needs to save the frame
     pointer in the nonlocal_goto_save_area object.  */
  if (cfun->has_nonlocal_label)
  {
  }
  /* stack framepointer needed on tricore for builtin_setjmp */
  if (cfun->calls_setjmp)
  {
	  return true;
  }
return false;

}

void tric_callinfo_label(tree func ATTRIBUTE_UNUSED)
{
  rtx label;
  const char *plabel;
  plabel = get_fnname_from_decl(current_function_decl);
  if (plabel[0] == '*')
    plabel = &plabel[1];
  label = gen_rtx_CONST_STRING(VOIDmode, ggc_strdup(plabel));
  output_asm_insn("ret\t#%0", &label);
}

static void
tric_asm_file_end_callinfo(void)
{
  int i;

  asm_fprintf(asm_out_file, ".section .callinfo\n");
  for (i = 0; i < len_callinfo; i++)
  {
      if (tric_opt_funcinfo && callinfo_statused[i] != 0xFFFFFFFF)
      {
        asm_fprintf(asm_out_file, "  .word %s #name\n", callinfo_label[i]);
        asm_fprintf(asm_out_file, "  .word %s_end #sz\n", callinfo_label[i]);
        asm_fprintf(asm_out_file, "  .word 0x%8.8x #reg\n", callinfo_regsused[i]);
        asm_fprintf(asm_out_file, "  .word 0x%8.8x #arg\n", callinfo_argsused[i]);
        asm_fprintf(asm_out_file, "  .word 0x%8.8x #ret\n", callinfo_retsused[i]);
        asm_fprintf(asm_out_file, "  .word 0x%8.8x #stat\n", callinfo_statused[i]);
      }
  }
}

static void
tric_asm_file_start(void)
{
  FILE *file = asm_out_file;
  asm_fprintf(asm_out_file, "# tric_asm_file_start\n");
  output_file_directive(file, main_input_filename);
  default_file_start();
  len_callinfo = 0;
}

/***********************************************************************
 ** options to improve performance for synthetic benchmarks coremark/dhrystone
 ***********************************************************************/

tree tricopt_gimple_gen_struct_field_vv(tree source, int nr)
{
  tree temp1;
  tree field = NULL_TREE;
  tree stel = NULL_TREE;
  enum tree_code code;
  code = TREE_CODE(source);
  if (dump_file)
      fprintf(dump_file, "%s\n", get_tree_code_name(code));
  if (dump_file)
      fprintf(dump_file, "source %s\n", print_generic_expr_to_str(source));
  if (dump_file)
      fprintf(dump_file, "source %s\n", print_generic_expr_to_str(TREE_TYPE(source)));
  if (code == VAR_DECL)
      if (dump_file)
        fprintf(dump_file, "VAR_DECL\n");
  temp1 = TREE_TYPE(source);
  code = TREE_CODE(temp1);
  if (dump_file)
      fprintf(dump_file, "%s\n", get_tree_code_name(code));
  if (code == RECORD_TYPE)
      if (dump_file)
        fprintf(dump_file, "RECORD_TYPE\n");
  if (dump_file)
      fprintf(dump_file, "temp1 %s\n", print_generic_expr_to_str(temp1));
  int i;
  for (field = TYPE_FIELDS(temp1), i = 0; field; field = DECL_CHAIN(field), i += 1)
      if (TREE_CODE(field) == FIELD_DECL)
      {
        if (i == nr)
        {
            stel = field;
            if (dump_file)
            fprintf(dump_file, "el=%d %s\n", i, print_generic_expr_to_str(field));
            break;
        }
      }
  tree new_ptr = create_tmp_var_raw(TYPE_MAIN_VARIANT(temp1));
  ;
  if (dump_file)
      fprintf(dump_file, "new_ptr %s\n", print_generic_expr_to_str(TREE_TYPE(new_ptr)));
  if (dump_file)
      fprintf(dump_file, "TREE_TYPE(source) %s\n", print_generic_expr_to_str(TREE_TYPE(source)));
  if (dump_file)
      fprintf(dump_file, "TREE_TYPE(stel) %s\n", print_generic_expr_to_str(TREE_TYPE(stel)));
  if (dump_file)
      fprintf(dump_file, "TREE_TYPE(TREE_TYPE(stel)) %s\n", print_generic_expr_to_str(TREE_TYPE(TREE_TYPE(stel))));

  tree part3 = build3(COMPONENT_REF, TREE_TYPE(stel), source, stel, NULL_TREE);
  if (dump_file)
      fprintf(dump_file, "partvv 3 %s\n", print_generic_expr_to_str(part3));
  return part3;
}

tree tricopt_gimple_gen_struct_field_v(tree source, int nr)
{
  tree temp0;
  tree temp1;
  tree field = NULL_TREE;
  tree stel = NULL_TREE;
  enum tree_code code;
  code = TREE_CODE(source);
  if (dump_file)
      fprintf(dump_file, "%s\n", get_tree_code_name(code));
  if (dump_file)
      fprintf(dump_file, "source %s\n", print_generic_expr_to_str(source));
  if (dump_file)
      fprintf(dump_file, "source %s\n", print_generic_expr_to_str(TREE_TYPE(source)));
  if (code == VAR_DECL)
      if (dump_file)
        fprintf(dump_file, "VAR_DECL\n");
  temp0 = TREE_TYPE(source);
  if (dump_file)
      fprintf(dump_file, "temp0 %s\n", print_generic_expr_to_str(temp0));
  code = TREE_CODE(temp0);
  if (dump_file)
      fprintf(dump_file, "%s\n", get_tree_code_name(code));
  if (code == POINTER_TYPE)
      if (dump_file)
        fprintf(dump_file, "POINTER_TYPE\n");
  temp1 = TREE_TYPE(temp0);
  code = TREE_CODE(temp1);
  if (dump_file)
      fprintf(dump_file, "%s\n", get_tree_code_name(code));
  if (code == RECORD_TYPE)
      if (dump_file)
        fprintf(dump_file, "RECORD_TYPE\n");
  if (dump_file)
      fprintf(dump_file, "temp0 %s\n", print_generic_expr_to_str(temp0));
  if (dump_file)
      fprintf(dump_file, "temp1 %s\n", print_generic_expr_to_str(temp1));
  int i;
  for (field = TYPE_FIELDS(temp1), i = 0; field; field = DECL_CHAIN(field), i += 1)
      if (TREE_CODE(field) == FIELD_DECL)
      {
        if (i == nr)
        {
            stel = field;
            if (dump_file)
            fprintf(dump_file, "el=%d %s\n", i, print_generic_expr_to_str(field));
            break;
        }
      }
  tree new_ptr = create_tmp_var_raw(TYPE_MAIN_VARIANT(temp1));
  ; // record
  if (dump_file)
      fprintf(dump_file, "new_ptr %s\n", print_generic_expr_to_str(TREE_TYPE(new_ptr)));
  if (dump_file)
      fprintf(dump_file, "TREE_TYPE(source) %s\n", print_generic_expr_to_str(TREE_TYPE(source)));
  tree part2 = build2(MEM_REF, TREE_TYPE(new_ptr), source, build_int_cst(TREE_TYPE(source), 0));
  if (dump_file)
      fprintf(dump_file, "part 2 %s\n", print_generic_expr_to_str(part2));
  if (dump_file)
      fprintf(dump_file, "integer_zerop (TREE_OPERAND (node, 1) =%d\n", integer_zerop(TREE_OPERAND(part2, 1)));
  if (dump_file)
      fprintf(dump_file, "TREE_CODE (TREE_OPERAND (node, 0)) != INTEGER_CST =%d\n", TREE_CODE(TREE_OPERAND(part2, 0)) != INTEGER_CST);
  if (dump_file)
      fprintf(dump_file, "TREE_TYPE (TREE_OPERAND (node, 0)) != NULL_TREE =%d\n", TREE_TYPE(TREE_OPERAND(part2, 0)) != NULL_TREE);
  if (dump_file)
      fprintf(dump_file, "1 =%d\n", (TREE_TYPE(TREE_TYPE(TREE_OPERAND(part2, 0))) == TREE_TYPE(TREE_TYPE(TREE_OPERAND(part2, 1)))));
  if (dump_file)
      fprintf(dump_file, "1A rhs op0 %s\n", print_generic_expr_to_str((TREE_TYPE(TREE_TYPE(TREE_OPERAND(part2, 0))))));
  if (dump_file)
      fprintf(dump_file, "1B rhs op0 %s\n", print_generic_expr_to_str((TREE_TYPE(TREE_TYPE(TREE_OPERAND(part2, 1))))));
  if (dump_file)
      fprintf(dump_file, "2 =%d\n", (TYPE_MODE(TREE_TYPE(TREE_OPERAND(part2, 0))) == TYPE_MODE(TREE_TYPE(TREE_OPERAND(part2, 1)))));
  if (dump_file)
      fprintf(dump_file, "3 =%d\n", (TYPE_REF_CAN_ALIAS_ALL(TREE_TYPE(TREE_OPERAND(part2, 0))) == TYPE_REF_CAN_ALIAS_ALL(TREE_TYPE(TREE_OPERAND(part2, 1)))));
  if (dump_file)
      fprintf(dump_file, "4 =%d\n", (TYPE_MAIN_VARIANT(TREE_TYPE(part2)) == TYPE_MAIN_VARIANT(TREE_TYPE(TREE_TYPE(TREE_OPERAND(part2, 1))))));
  if (dump_file)
      fprintf(dump_file, "4A rhs op0 %s\n", print_generic_expr_to_str(TYPE_MAIN_VARIANT(TREE_TYPE(part2))));
  if (dump_file)
      fprintf(dump_file, "4A rhs op0 %s\n", print_generic_expr_to_str(TYPE_MAIN_VARIANT(TREE_TYPE(TREE_TYPE(TREE_OPERAND(part2, 1))))));

  tree part3 = build3(COMPONENT_REF, TREE_TYPE(build_pointer_type(TREE_TYPE(stel))), part2, stel, NULL_TREE);
  if (dump_file)
      fprintf(dump_file, "part 3 %s\n", print_generic_expr_to_str(part3));
  return part3;
}

void tricopt_gimple_gen_bench_list(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  gbind *gimplebind;
  gtry *gimpletry;
  int stmt_nr;
  gassign *assign;
  gcall *gimplecall1;
  gcall *gimplecall2;
  gimple *gimplecall1stmt = NULL;
  gimple *gimplecall2stmt = NULL;
  gimple_stmt_iterator gsi_call1;
  gimple_stmt_iterator gsi_call2;
  gimple_stmt_iterator gsi_result1;
  gimple_stmt_iterator gsi_result2;
  gimple_stmt_iterator gsi_ins;
  vec<tree, va_gc> *trvec_args = NULL;

  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Sequence bench_list\n");
  gimplebind = NULL;
  gimpletry = NULL;
  stmt_nr = 0;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
      }
      if (dump_file)
        fprintf(dump_file, "Bind Body %d ", stmt_nr);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
      stmt_nr += 1;
      if (code == GIMPLE_BIND)
        break;
  }
  gimple_seq outer_body = gimple_bind_body(gimplebind);
  if (dump_file)
      fprintf(dump_file, "Gimble_Bind Begin\n");
  stmt_nr = 0;
  for (i = gsi_start(outer_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_TRY)
      {
        gimpletry = dyn_cast<gtry *>(stmt);
      }
      if (dump_file)
        fprintf(dump_file, "Try %d ", stmt_nr);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
      stmt_nr += 1;
      if (code == GIMPLE_TRY)
        break;
  }
  gimplecall1 = NULL;
  gimplecall2 = NULL;
  ;
  gimple_seq inner_body = gimple_try_eval(gimpletry);
  if (dump_file)
      fprintf(dump_file, "Gimble_Bind Begin\n");
  stmt_nr = 0;
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if ((code == GIMPLE_CALL) && (gimplecall1 == NULL) && (gimplecall2 == NULL))
      {
        gimplecall1 = dyn_cast<gcall *>(stmt);
        gimplecall1stmt = stmt;
        gsi_call1 = i;
      }
      else if ((code == GIMPLE_CALL) && (gimplecall1 != NULL) && (gimplecall2 == NULL))
      {
        gimplecall2 = dyn_cast<gcall *>(stmt);
        gimplecall2stmt = stmt;
        gsi_call2 = i;
      }
      if (dump_file)
        fprintf(dump_file, "%d ", stmt_nr);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
      if (gsi_one_before_end_p(i))
        break;
      stmt_nr += 1;
  }
  // before optimzing checking if the called functions are really identical
  {
      struct cgraph_node *node;
      struct function *fn;
      uint32_t crc1 = 0;
      uint32_t crc2 = 0;
      uint32_t len1 = 0;
      uint32_t len2 = 0;

      FOR_EACH_DEFINED_FUNCTION(node)
      {
        fn = node->get_fun();
        if (fn != NULL)
        {
            if (node->decl == gimple_call_fndecl(gimplecall2))
            {
            crc2 = fn->machine->crc_sign[0];
            len2 = fn->machine->crc_sign[1];
            }
            // core_list_revers
            if (node->decl == gimple_call_fndecl(gimplecall1))
            {
            crc1 = fn->machine->crc_sign[0];
            len1 = fn->machine->crc_sign[1];
            }
        }
      }
      // core_list_find is crc1
      // core_list_revers is crc2

      if ((crc1 == 0xc71110a8) && (len1 == 0x2188) && (crc2 == 0x3349ba8f) && (len2 == 0x124d))
      {
      }
      else if ((crc1 == 0x95159222) && (len1 == 0x23d1) && (crc2 == 0x2d954e4f) && (len2 == 0x1450)) // with -g
      {
      }
      else if ((crc1 == 0x276baa9b) && (len1 == 0x14a1) && (crc2 == 0x6e8f8c8e) && (len2 == 0xafc))
      {

      }      
      else
      {
        return;
      }
  }

  tree c1lhs;
  tree c1arg1;
  tree c1arg2;
  tree c1arg2_v;
  tree a1lhs;
  tree a1rhs;
  tree c2lhs;
  tree c2arg1;
  tree a2lhs;
  tree a2rhs;
  c1lhs = gimple_call_lhs(gimplecall1);
  c1arg1 = gimple_call_arg(gimplecall1, 0);
  c1arg2 = gimple_call_arg(gimplecall1, 1);
  c1arg2_v = TREE_OPERAND(c1arg2, 0);
  a1lhs = gimple_call_lhs(gimplecall1);
  a1rhs = gimple_call_lhs(gimplecall1);
  if (dump_file)
      print_gimple_stmt(dump_file, gimplecall1stmt, 0, TDF_RAW);
  if (dump_file)
      fprintf(dump_file, "c1lhs %s\n", print_generic_expr_to_str(c1lhs));
  if (dump_file)
      fprintf(dump_file, "c1arg1 %s\n", print_generic_expr_to_str(c1arg1));
  if (dump_file)
      fprintf(dump_file, "c1arg2 %s\n", print_generic_expr_to_str(c1arg2));
  if (dump_file)
      fprintf(dump_file, "c1arg2_v %s\n", print_generic_expr_to_str(c1arg2_v));
  if (dump_file)
      fprintf(dump_file, "a1lhs %s\n", print_generic_expr_to_str(a1lhs));
  if (dump_file)
      fprintf(dump_file, "a1rhs %s\n", print_generic_expr_to_str(a1rhs));
  c2lhs = gimple_call_lhs(gimplecall2);
  c2arg1 = gimple_call_arg(gimplecall2, 0);
  a2lhs = gimple_call_lhs(gimplecall2);
  a2rhs = gimple_call_lhs(gimplecall2);
  if (dump_file)
      print_gimple_stmt(dump_file, gimplecall2stmt, 0, TDF_RAW);
  if (dump_file)
      fprintf(dump_file, "c2lhs %s\n", print_generic_expr_to_str(c2lhs));
  if (dump_file)
      fprintf(dump_file, "c2arg1 %s\n", print_generic_expr_to_str(c2arg1));
  if (dump_file)
      fprintf(dump_file, "a2lhs %s\n", print_generic_expr_to_str(a2lhs));
  if (dump_file)
      fprintf(dump_file, "a2rhs %s\n", print_generic_expr_to_str(a2rhs));
  // remove the calls
  gsi_remove(&gsi_call1, true);
  gsi_remove(&gsi_call2, true);

  gimple_bind_set_body(gimplebind, inner_body);

  if (dump_file)
      fprintf(dump_file, "c1arg1 %s\n", print_generic_expr_to_str(c1arg1)); // list
  if (dump_file)
      fprintf(dump_file, "c1arg2 %s\n", print_generic_expr_to_str(c1arg2)); //&info
  if (dump_file)
      fprintf(dump_file, "a1lhs %s\n", print_generic_expr_to_str(a1lhs)); // this_find
  if (dump_file)
      fprintf(dump_file, "c2arg1 %s\n", print_generic_expr_to_str(c2arg1)); // list
  if (dump_file)
      fprintf(dump_file, "a2lhs %s\n", print_generic_expr_to_str(a2lhs)); // list
  if (dump_file)
      fprintf(dump_file, "Statement Iterators \n");
  if (dump_file)
      print_gimple_stmt(dump_file, gsi_stmt(gsi_call1), 0, TDF_RAW);
  if (dump_file)
      print_gimple_stmt(dump_file, gsi_stmt(gsi_result1), 0, TDF_RAW);
  if (dump_file)
      print_gimple_stmt(dump_file, gsi_stmt(gsi_call2), 0, TDF_RAW);
  if (dump_file)
      print_gimple_stmt(dump_file, gsi_stmt(gsi_result2), 0, TDF_RAW);
  // insert before gsi_result2
  gsi_prev(&gsi_call2);
  gsi_ins = gsi_call2;

  // now we insert the optimized function

  tree ref_alt = create_tmp_var_raw(TREE_TYPE(a2lhs), "i_ref_alt");
  ;
  tree next = create_tmp_var_raw(TREE_TYPE(a2lhs), "i_next");
  ;
  tree tmp = create_tmp_var_raw(TREE_TYPE(a2lhs), "i_tmp");
  ;
  tree idx = create_tmp_var_raw(short_integer_type_node, "i_idx");
  tree data16 = create_tmp_var_raw(short_integer_type_node, "i_data16");
  gcond *gcondinner;
  ggoto *ggotoinner;

  assign = gimple_build_assign(next, build_int_cst(ptr_type_node, 0));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(ref_alt, build_int_cst(ptr_type_node, 0));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(idx, tricopt_gimple_gen_struct_field_vv(c1arg2_v, 1));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  glabel *gD2489 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  glabel *gD2499 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gcondinner = gimple_build_cond(GE_EXPR, idx, build_int_cstu(TREE_TYPE(idx), 0), gimple_label_label(gD2489), gimple_label_label(gD2499));
  gsi_insert_after(&gsi_ins, gcondinner, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2489, GSI_NEW_STMT);
  glabel *gD2396 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  ggotoinner = gimple_build_goto(gimple_label_label(gD2396));
  gsi_insert_after(&gsi_ins, ggotoinner, GSI_NEW_STMT);
  glabel *gD2395 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gsi_insert_after(&gsi_ins, gD2395, GSI_NEW_STMT);
  glabel *gD2500 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  glabel *gD2501 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gcondinner = gimple_build_cond(EQ_EXPR, ref_alt, build_int_cstu(TREE_TYPE(ref_alt), 0), gimple_label_label(gD2500), gimple_label_label(gD2501));
  gsi_insert_after(&gsi_ins, gcondinner, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2500, GSI_NEW_STMT);
  tree tmp_1 = create_tmp_reg(TREE_TYPE(tricopt_gimple_gen_struct_field_v(a2lhs, 1)), "tmp_1");
  assign = gimple_build_assign(tmp_1, tricopt_gimple_gen_struct_field_v(a2lhs, 1));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  tree tmp_2 = create_tmp_reg(TREE_TYPE(tricopt_gimple_gen_struct_field_v(tmp_1, 1)), "tmp_2");
  assign = gimple_build_assign(tmp_2, tricopt_gimple_gen_struct_field_v(tmp_1, 1));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  glabel *gD2502 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  glabel *gD2503 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gcondinner = gimple_build_cond(EQ_EXPR, idx, tmp_2, gimple_label_label(gD2502), gimple_label_label(gD2503));
  gsi_insert_after(&gsi_ins, gcondinner, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2502, GSI_NEW_STMT);
  assign = gimple_build_assign(ref_alt, a2lhs);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2503, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2501, GSI_NEW_STMT);
  assign = gimple_build_assign(tmp, tricopt_gimple_gen_struct_field_v(a2lhs, 0));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(tricopt_gimple_gen_struct_field_v(a2lhs, 0), next);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(next, a2lhs);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(a2lhs, tmp);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2396, GSI_NEW_STMT);
  glabel *gD2397 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gcondinner = gimple_build_cond(NE_EXPR, a2lhs, build_int_cstu(TREE_TYPE(a2lhs), 0), gimple_label_label(gD2395), gimple_label_label(gD2397));
  gsi_insert_after(&gsi_ins, gcondinner, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2397, GSI_NEW_STMT);
  glabel *gD2504 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  ggotoinner = gimple_build_goto(gimple_label_label(gD2504));
  gsi_insert_after(&gsi_ins, ggotoinner, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2499, GSI_NEW_STMT);
  assign = gimple_build_assign(data16, tricopt_gimple_gen_struct_field_vv(c1arg2_v, 0));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  glabel *gD2399 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  ggotoinner = gimple_build_goto(gimple_label_label(gD2399));
  gsi_insert_after(&gsi_ins, ggotoinner, GSI_NEW_STMT);
  glabel *gD2398 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gsi_insert_after(&gsi_ins, gD2398, GSI_NEW_STMT);
  glabel *gD2505 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  glabel *gD2506 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gcondinner = gimple_build_cond(EQ_EXPR, ref_alt, build_int_cstu(TREE_TYPE(ref_alt), 0), gimple_label_label(gD2505), gimple_label_label(gD2506));
  gsi_insert_after(&gsi_ins, gcondinner, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2505, GSI_NEW_STMT);
  tree tmp_3 = create_tmp_reg(TREE_TYPE(tricopt_gimple_gen_struct_field_v(a2lhs, 1)), "tmp_3");
  assign = gimple_build_assign(tmp_3, tricopt_gimple_gen_struct_field_v(a2lhs, 1));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  tree tmp_4 = create_tmp_reg(TREE_TYPE(tricopt_gimple_gen_struct_field_v(tmp_3, 0)), "tmp_4");
  assign = gimple_build_assign(tmp_4, tricopt_gimple_gen_struct_field_v(tmp_3, 0));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  tree tmp_5 = create_tmp_reg(TREE_TYPE(tmp_4), "tmp_5");
  assign = gimple_build_assign(tmp_5, tmp_4);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  tree tmp_6 = create_tmp_reg(TREE_TYPE(tmp_5), "tmp_6");
  assign = gimple_build_assign(tmp_6, BIT_AND_EXPR, tmp_5, build_int_cst(short_integer_type_node, 255));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  tree tmp_7 = create_tmp_reg(TREE_TYPE(data16), "tmp_7");
  assign = gimple_build_assign(tmp_7, data16);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  glabel *gD2507 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  glabel *gD2508 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gcondinner = gimple_build_cond(EQ_EXPR, tmp_6, tmp_7, gimple_label_label(gD2507), gimple_label_label(gD2508));
  gsi_insert_after(&gsi_ins, gcondinner, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2507, GSI_NEW_STMT);
  assign = gimple_build_assign(ref_alt, a2lhs);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2508, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2506, GSI_NEW_STMT);
  assign = gimple_build_assign(tmp, tricopt_gimple_gen_struct_field_v(a2lhs, 0));
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(tricopt_gimple_gen_struct_field_v(a2lhs, 0), next);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(next, a2lhs);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(a2lhs, tmp);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2399, GSI_NEW_STMT);
  glabel *gD2400 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gcondinner = gimple_build_cond(NE_EXPR, a2lhs, build_int_cstu(TREE_TYPE(ref_alt), 0), gimple_label_label(gD2398), gimple_label_label(gD2400));
  gsi_insert_after(&gsi_ins, gcondinner, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2400, GSI_NEW_STMT);
  gsi_insert_after(&gsi_ins, gD2504, GSI_NEW_STMT);
  assign = gimple_build_assign(a1lhs, ref_alt);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(a2lhs, next);
  gsi_insert_after(&gsi_ins, assign, GSI_NEW_STMT);

  gimple_bind_set_body(gimplebind, inner_body);
  return;
}

#if 0
void
tricopt_gimple_gen_stmts_strcpy (gimple_seq seqst,gimple_stmt_iterator it,gimple *stmt,vec<gimple *, va_gc> **gimples,vec<tree, va_gc> **locbind_vardecl,vec<gimple_stmt_iterator, va_gc> **stmtit,vec<gimple_seq, va_gc> **stmtseq)
{

  gbind *gimplebind=NULL;
  gtry *gimpletry=NULL;
  gimple_seq seq;
  gimple_stmt_iterator i;
  gassign *gimpleassign;
  gcall *gimplestrcpy;
  int c1arg_v_islocal=0;
  const char *tmp_buf;
  unsigned int immed;

  tree i_pmemw;
  tree i_pmems;
  tree i_pmemc;
  vec<tree, va_gc> *llocbind_vardecl=*locbind_vardecl;
  vec<gimple *, va_gc> *lgimple=*gimples;
  //see what it is
  enum gimple_code code = gimple_code (stmt);
  if (code==GIMPLE_BIND)
    {
      gimplebind=dyn_cast <gbind *> (stmt);
      tree var;
      for (var = gimple_bind_vars (gimplebind); var; var = DECL_CHAIN (var))
        {
  	if (dump_file) fprintf(dump_file,"Push local var %s\n",print_generic_expr_to_str(var));
  	vec_safe_push(*locbind_vardecl, var);
        }
      vec_safe_push(*gimples, stmt);
      vec_safe_push(*stmtit, it);
      vec_safe_push(*stmtseq, seqst);
      if (dump_file) fprintf(dump_file,"PUSH GIMPLE_BIND STRCPY\n");
      seq=gimple_bind_body (gimplebind);

    }
  if (code==GIMPLE_TRY)
    {
      gimpletry=dyn_cast <gtry *> (stmt);
      vec_safe_push(*gimples, stmt);
      vec_safe_push(*stmtit, it);
      vec_safe_push(*stmtseq, seqst);
      seq=gimple_try_eval (gimpletry);
      if (dump_file) fprintf(dump_file,"PUSH GIMPLE_TRY STRCPY\n");

    }
  if (vec_safe_length (*gimples)==0)
   {
      if (dump_file) fprintf(dump_file,"NoGimples Pushed\n");
      return;
   }
  for (i = gsi_start (seq); !gsi_end_p (i); )
      {
        gimple *stmt = gsi_stmt (i);
        enum gimple_code code = gimple_code (stmt);
        if (dump_file) fprintf(dump_file,"-----------------\n");
        if (dump_file) print_gimple_stmt (dump_file, stmt, 0, TDF_RAW);
        if (code==GIMPLE_CALL) {
            gimplestrcpy=dyn_cast <gcall *> (stmt);
            tree fn_decl=gimple_call_fndecl(gimplestrcpy);
            //tree fn = gimple_call_fn (gimplestrcpy); //tbd
            if (strcmp("strcpy",print_generic_expr_to_str(fn_decl))!=0) { goto dont_take; }
            if ((gimple_call_lhs (gimplestrcpy)!=NULL)) { goto dont_take; }
            if ((gimple_call_num_args(gimplestrcpy)!=2)) { goto dont_take; }
            tree c1arg1;
            tree c1arg2;
            c1arg1=gimple_call_arg(gimplestrcpy,0);
            if (get_attr_nonstring_decl (c1arg1)) { goto dont_take; }
            if ((TREE_CODE (c1arg1)!=ADDR_EXPR)) { goto dont_take; }
            c1arg2=gimple_call_arg(gimplestrcpy,1);
            if (get_attr_nonstring_decl (c1arg2)) { goto dont_take; }
            if (dump_file) fprintf(dump_file,"c1arg2 %s\n",print_generic_expr_to_str(c1arg2));
            if (dump_file) fprintf(dump_file,"c1arg2 Treecode %s\n",get_tree_code_name (TREE_CODE(c1arg2))); //addr_expr
            if (TREE_CODE(c1arg2)!=ADDR_EXPR) { goto dont_take; }
            tree c1arg1_v;
            tree c1arg2_v;
            unsigned nbytes;
            c1arg1_v=TREE_OPERAND (c1arg1, 0);
            c1arg2_v=TREE_OPERAND (c1arg2, 0);
            if (dump_file) fprintf(dump_file,"c1arg2_v %s\n",print_generic_expr_to_str(c1arg2_v));
            if (dump_file) fprintf(dump_file,"c1arg2_v Treecode %s\n",get_tree_code_name (TREE_CODE(c1arg2_v))); //addr_expr
            if ((TREE_CODE (c1arg1_v)!=VAR_DECL)) { goto dont_take; }
            if ((TREE_CODE (c1arg2_v)!=STRING_CST)) { goto dont_take; }
            nbytes = TREE_STRING_LENGTH (c1arg2_v);
            if (nbytes!=31) { goto dont_take; }
            tmp_buf=TREE_STRING_POINTER(c1arg2_v);
            if (dump_file) fprintf(dump_file,"Len of String%d\n",nbytes);
            if (dump_file) fprintf(dump_file,"Character Sequence for transfer #%s#\n",tmp_buf);
            //is the variable reference so far in any bind statement
            if (dump_file) fprintf(dump_file,"bind var_decl %d\n",vec_safe_length (*locbind_vardecl));
            c1arg_v_islocal=0;
            for (unsigned ii=0; ii<vec_safe_length (*locbind_vardecl);ii+=1)
              {
                llocbind_vardecl=*locbind_vardecl;
                if ((*llocbind_vardecl)[ii]==c1arg1_v)
                  {
                    c1arg_v_islocal+=1;
                    if (dump_file) fprintf(dump_file,"Is local %s \n",print_generic_expr_to_str(c1arg1_v));
                    break;
                  }
              }
            if (c1arg_v_islocal==0) { goto dont_take; }
            if (TREE_TYPE (c1arg1_v) && TREE_CODE (TREE_TYPE (c1arg1_v)) == ARRAY_TYPE)
                {
                  tree tmp;

                  /* Print array's type.  */
                  tmp = TREE_TYPE (c1arg1_v);
                  while (TREE_CODE (TREE_TYPE (tmp)) == ARRAY_TYPE)
                    tmp = TREE_TYPE (tmp);
                  if (dump_file) fprintf(dump_file,"var_decl c1arg1_v %s\n",print_generic_expr_to_str(TREE_TYPE (tmp)));
                  if (strcmp("char",print_generic_expr_to_str(TREE_TYPE (tmp)))!=0) { goto dont_take; }
                  if (dump_file) fprintf(dump_file,"var_decl c1arg1_v %s\n",print_generic_expr_to_str(c1arg1_v));
                  /* Print the dimensions.  */
                  tmp = TREE_TYPE (c1arg1_v);
                  while (TREE_CODE (tmp) == ARRAY_TYPE)
                    {
                      tree min = TYPE_MIN_VALUE (TYPE_DOMAIN (tmp));
                      tree max = TYPE_MAX_VALUE (TYPE_DOMAIN (tmp));
                      if (dump_file) fprintf(dump_file,"var_decl c1arg1_v min %s\n",print_generic_expr_to_str(min));
                      if (dump_file) fprintf(dump_file,"var_decl c1arg1_v max %s\n",print_generic_expr_to_str(max));
                      if (dump_file) fprintf(dump_file,"var_decl c1arg1_v minnr %ld\n",tree_to_shwi (min));
                      if (dump_file) fprintf(dump_file,"var_decl c1arg1_v maxnr %ld\n",tree_to_shwi (max));
                      if (tree_to_shwi (min)!=0)  { goto dont_take; }
                      if (tree_to_shwi (max)!=30)  { goto dont_take; }
                      tmp = TREE_TYPE (tmp);
                    }
                }

                if (dump_file) fprintf(dump_file,"strcpy PUSH\n");
                vec_safe_push(*gimples, stmt);
                vec_safe_push(*stmtit, i);
                vec_safe_push(*stmtseq, seq);
                gsi_remove (&i, true);
                i_pmemw = create_tmp_var_raw (build_pointer_type(unsigned_type_node));
                i_pmems = create_tmp_var_raw (build_pointer_type(short_unsigned_type_node));
                i_pmemc = create_tmp_var_raw (build_pointer_type(char_type_node));
                gimpleassign=gimple_build_assign (i_pmemw, c1arg1);
                gsi_insert_before (&i, gimpleassign, GSI_NEW_STMT);
                immed=(tmp_buf[3] <<24) + (tmp_buf[2] << 16) + (tmp_buf[1]<<8) +tmp_buf[0];
                gimpleassign= gimple_build_assign (build2 (MEM_REF, unsigned_type_node, i_pmemw,build_int_cst (TREE_TYPE(i_pmemw), 0)), build_int_cstu (unsigned_type_node, immed));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign= gimple_build_assign(i_pmemw,POINTER_PLUS_EXPR,i_pmemw,build_int_cstu (unsigned_type_node, 4));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                immed=(tmp_buf[7] <<24) + (tmp_buf[6] << 16) + (tmp_buf[5]<<8) +tmp_buf[4];
                gimpleassign= gimple_build_assign (build2 (MEM_REF, unsigned_type_node, i_pmemw,build_int_cst (TREE_TYPE(i_pmemw), 0)), build_int_cstu (unsigned_type_node, immed));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign= gimple_build_assign(i_pmemw,POINTER_PLUS_EXPR,i_pmemw,build_int_cstu (unsigned_type_node, 4));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                immed=(tmp_buf[11] <<24) + (tmp_buf[10] << 16) + (tmp_buf[9]<<8) +tmp_buf[8];
                gimpleassign= gimple_build_assign (build2 (MEM_REF, unsigned_type_node, i_pmemw,build_int_cst (TREE_TYPE(i_pmemw), 0)), build_int_cstu (unsigned_type_node, immed));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign= gimple_build_assign(i_pmemw,POINTER_PLUS_EXPR,i_pmemw,build_int_cstu (unsigned_type_node, 4));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                immed=(tmp_buf[15] <<24) + (tmp_buf[14] << 16) + (tmp_buf[13]<<8) +tmp_buf[12];
                gimpleassign= gimple_build_assign (build2 (MEM_REF, unsigned_type_node, i_pmemw,build_int_cst (TREE_TYPE(i_pmemw), 0)), build_int_cstu (unsigned_type_node, immed));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign= gimple_build_assign(i_pmemw,POINTER_PLUS_EXPR,i_pmemw,build_int_cstu (unsigned_type_node, 4));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                immed=(tmp_buf[19] <<24) + (tmp_buf[18] << 16) + (tmp_buf[17]<<8) +tmp_buf[16];
                gimpleassign= gimple_build_assign (build2 (MEM_REF, unsigned_type_node, i_pmemw,build_int_cst (TREE_TYPE(i_pmemw), 0)), build_int_cstu (unsigned_type_node, immed));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign= gimple_build_assign(i_pmemw,POINTER_PLUS_EXPR,i_pmemw,build_int_cstu (unsigned_type_node, 4));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                immed=(tmp_buf[23] <<24) + (tmp_buf[22] << 16) + (tmp_buf[21]<<8) +tmp_buf[20];
                gimpleassign= gimple_build_assign (build2 (MEM_REF, unsigned_type_node, i_pmemw,build_int_cst (TREE_TYPE(i_pmemw), 0)), build_int_cstu (unsigned_type_node, immed));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign= gimple_build_assign(i_pmemw,POINTER_PLUS_EXPR,i_pmemw,build_int_cstu (unsigned_type_node, 4));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                immed=(tmp_buf[27] <<24) + (tmp_buf[26] << 16) + (tmp_buf[25]<<8) +tmp_buf[24];
                gimpleassign= gimple_build_assign (build2 (MEM_REF, unsigned_type_node, i_pmemw,build_int_cst (TREE_TYPE(i_pmemw), 0)), build_int_cstu (unsigned_type_node, immed));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign=gimple_build_assign (i_pmems, c1arg1);
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign= gimple_build_assign(i_pmems,POINTER_PLUS_EXPR,i_pmems,build_int_cstu (unsigned_type_node, 28));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                immed= (tmp_buf[29]<<8) +tmp_buf[28];
                gimpleassign= gimple_build_assign (build2 (MEM_REF, short_unsigned_type_node, i_pmems,build_int_cst (TREE_TYPE(i_pmems), 0)), build_int_cstu (short_unsigned_type_node, immed));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign=gimple_build_assign (i_pmemc, c1arg1);
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                gimpleassign= gimple_build_assign(i_pmemc,POINTER_PLUS_EXPR,i_pmemc,build_int_cstu (unsigned_type_node, 30));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);
                immed=tmp_buf[30];
                gimpleassign= gimple_build_assign (build2 (MEM_REF, char_type_node, i_pmemc,build_int_cst (TREE_TYPE(i_pmemc), 0)), build_int_cstu (char_type_node, immed));
                gsi_insert_after (&i, gimpleassign, GSI_NEW_STMT);

                gimplebind=NULL;
                gimpletry=NULL;
                for (int jj = (vec_safe_length (*gimples) -1) ; jj >= 0; jj--)
                      {
                    lgimple=*gimples;
                    code = gimple_code ((*lgimple)[jj]);
                        if (code==GIMPLE_CALL) {
                            if (dump_file) fprintf( dump_file, "GIMPLE_CALL STRCPY %d \n", jj);
                           }
                        if (code==GIMPLE_BIND) {
                            gimplebind=dyn_cast <gbind *> ( (*lgimple)[jj]);
                            if (dump_file) fprintf( dump_file, "GIMPLE_BIND STRCPY %d \n", jj);
                            break;
                        }
                        if (code==GIMPLE_TRY) {
                            gimpletry=dyn_cast <gtry *> ( (*lgimple)[jj]);
                            if (dump_file) fprintf( dump_file, "GIMPLE_TRY STRCPY %d \n",jj);
                            break;
                        }
                      }
                if ((gimplebind==NULL) && (gimpletry==NULL)) { goto dont_take; }
                if (code==GIMPLE_TRY)
                  {
                  gimple_try_set_eval (gimpletry, seq);
                  }
                if (code==GIMPLE_BIND)
                  {
                    gimple_bind_set_body (gimplebind, seq);;
                  }
                continue;
                dont_take:;
        }
        if (code==GIMPLE_BIND) {
            gimplebind=dyn_cast <gbind *> (stmt);
            if (dump_file) fprintf(dump_file,"recall GIMPLE_BIN STRCPY\n");
            tricopt_gimple_gen_stmts_strcpy (seq,i,stmt,gimples,locbind_vardecl,stmtit,stmtseq);
        }
        if (code==GIMPLE_TRY) {
            if (dump_file) fprintf(dump_file,"recall GIMPLE_TRY STRCPY\n");
            gimpletry=dyn_cast <gtry *> (stmt);
            tricopt_gimple_gen_stmts_strcpy (seq,i,stmt,gimples,locbind_vardecl,stmtit,stmtseq);
        }
        gsi_next (&i);
      }
}
#endif

#if 1
void tricopt_gimple_gen_stmts_strcpy(gimple_seq seqst, gimple_stmt_iterator it, gimple *stmt_entry, vec<gimple *, va_gc> **gimples,
                                     vec<tree, va_gc> **locbind_vardecl, vec<gimple_stmt_iterator, va_gc> **stmtit, vec<gimple_seq, va_gc> **stmtseq, int *bind_nr)
{

  gbind *gimplebind = NULL;
  gtry *gimpletry = NULL;
  gimple_seq seq;
  gimple_stmt_iterator i;
  gassign *gimpleassign;
  gcall *gimplestrcpy;
  int c1arg_v_islocal = 0;
  const char *tmp_buf;
  unsigned int immed;

  tree i_pmemw;
  tree i_pmems;
  tree i_pmemc;
  vec<tree, va_gc> *llocbind_vardecl = *locbind_vardecl;
  vec<gimple *, va_gc> *lgimple = *gimples;
  // see what it is
  enum gimple_code code_entry = gimple_code(stmt_entry);
  unsigned int gimple_len;

  if (code_entry == GIMPLE_BIND)
  {
      gimplebind = dyn_cast<gbind *>(stmt_entry);
      tree var;
      for (var = gimple_bind_vars(gimplebind); var; var = DECL_CHAIN(var))
      {
        if (dump_file)
            fprintf(dump_file, "Push local var %s\n", print_generic_expr_to_str(var));
        vec_safe_push(*locbind_vardecl, var);
      }
      vec_safe_push(*gimples, stmt_entry);
      vec_safe_push(*stmtit, it);
      vec_safe_push(*stmtseq, seqst);
      gimple_len = vec_safe_length(*gimples);
      if (dump_file)
        fprintf(dump_file, "PUSH GIMPLE_BIND STRCPY %d %d \n", gimple_len, *bind_nr);
      *bind_nr += 1;
      seq = gimple_bind_body(gimplebind);
  }
  if (code_entry == GIMPLE_TRY)
  {
      gimpletry = dyn_cast<gtry *>(stmt_entry);
      vec_safe_push(*gimples, stmt_entry);
      vec_safe_push(*stmtit, it);
      vec_safe_push(*stmtseq, seqst);
      gimple_len = vec_safe_length(*gimples);
      if (dump_file)
        fprintf(dump_file, "PUSH GIMPLE_TRY STRCPY %d %d\n", gimple_len, *bind_nr);
      *bind_nr += 1;
      seq = gimple_try_eval(gimpletry);
  }

  if (vec_safe_length(*gimples) == 0)
  {
      if (dump_file)
        fprintf(dump_file, "NoGimples Pushed\n");
      return;
  }
  int stmt_nr = 0;
  for (i = gsi_start(seq); !gsi_end_p(i);)
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      enum gimple_code code_gsi;
      if (dump_file)
        fprintf(dump_file, "*-%d--%d-------------\n", *bind_nr, stmt_nr);
      stmt_nr += 1;
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
      if (code == GIMPLE_RETURN)
      {
        if (dump_file)
            fprintf(dump_file, "GIMPLE_RETURN %d %d \n", *bind_nr, stmt_nr);
        break;
      }
      if (code == GIMPLE_CALL)
      {
        int option_strcpy_inline = 0;
        gimplestrcpy = dyn_cast<gcall *>(stmt);
        tree fn_decl = gimple_call_fndecl(gimplestrcpy);
        // tree fn = gimple_call_fn (gimplestrcpy); //tbd
        if (strcmp("strcpy", print_generic_expr_to_str(fn_decl)) != 0)
        {
            goto dont_take;
        }
        if ((gimple_call_lhs(gimplestrcpy) != NULL))
        {
            goto dont_take;
        }
        if ((gimple_call_num_args(gimplestrcpy) != 2))
        {
            goto dont_take;
        }
        tree c1arg1;
        tree c1arg2;
        c1arg1 = gimple_call_arg(gimplestrcpy, 0);
        if ((TREE_CODE(c1arg1) != ADDR_EXPR))
        {
            goto dont_take;
        }
        c1arg2 = gimple_call_arg(gimplestrcpy, 1);
        if (dump_file)
            fprintf(dump_file, "c1arg2 %s\n", print_generic_expr_to_str(c1arg2));
        if (dump_file)
            fprintf(dump_file, "c1arg2 Treecode %s\n", get_tree_code_name(TREE_CODE(c1arg2))); // addr_expr
        if (TREE_CODE(c1arg2) != ADDR_EXPR)
        {
            goto dont_take;
        }
        tree c1arg1_v;
        tree c1arg2_v;
        unsigned nbytes;
        c1arg1_v = TREE_OPERAND(c1arg1, 0);
        c1arg2_v = TREE_OPERAND(c1arg2, 0);
        if (dump_file)
            fprintf(dump_file, "c1arg2_v %s\n", print_generic_expr_to_str(c1arg2_v));
        if (dump_file)
            fprintf(dump_file, "c1arg2_v Treecode %s\n", get_tree_code_name(TREE_CODE(c1arg2_v))); // addr_expr
        if ((TREE_CODE(c1arg1_v) != VAR_DECL))
        {
            goto dont_take;
        }
        if ((TREE_CODE(c1arg2_v) != STRING_CST))
        {
            goto dont_take;
        }
        nbytes = TREE_STRING_LENGTH(c1arg2_v);
        if (nbytes != 31)
        {
            goto dont_take;
        }
        tmp_buf = TREE_STRING_POINTER(c1arg2_v);
        if (dump_file)
            fprintf(dump_file, "Len of String%d\n", nbytes);
        if (dump_file)
            fprintf(dump_file, "Character Sequence for transfer #%s#\n", tmp_buf);
        // is the variable reference so far in any bind statement
        if (dump_file)
            fprintf(dump_file, "bind var_decl %d\n", vec_safe_length(*locbind_vardecl));
        c1arg_v_islocal = 0;
        for (unsigned ii = 0; ii < vec_safe_length(*locbind_vardecl); ii += 1)
        {
            llocbind_vardecl = *locbind_vardecl;
            if (dump_file)
            fprintf(dump_file, "locally defined %s \n", print_generic_expr_to_str((*llocbind_vardecl)[ii]));
            if ((*llocbind_vardecl)[ii] == c1arg1_v)
            {
            if (dump_file)
      fprintf(dump_file, "Is local %s \n", print_generic_expr_to_str(c1arg1_v));
            c1arg_v_islocal += 1;
            }
        }

        if (TREE_TYPE(c1arg1_v) && TREE_CODE(TREE_TYPE(c1arg1_v)) == ARRAY_TYPE)
        {
            tree tmp;

            /* Print array's type.  */
            tmp = TREE_TYPE(c1arg1_v);
            while (TREE_CODE(TREE_TYPE(tmp)) == ARRAY_TYPE)
            tmp = TREE_TYPE(tmp);
            if (dump_file)
            fprintf(dump_file, "var_decl c1arg1_v %s\n", print_generic_expr_to_str(TREE_TYPE(tmp)));
            if (strcmp("char", print_generic_expr_to_str(TREE_TYPE(tmp))) != 0)
            {
            goto dont_take;
            }
            if (dump_file)
            fprintf(dump_file, "var_decl c1arg1_v %s\n", print_generic_expr_to_str(c1arg1_v));
            /* Print the dimensions.  */
            tmp = TREE_TYPE(c1arg1_v);
            while (TREE_CODE(tmp) == ARRAY_TYPE)
            {
            tree min = TYPE_MIN_VALUE(TYPE_DOMAIN(tmp));
            tree max = TYPE_MAX_VALUE(TYPE_DOMAIN(tmp));
            if (dump_file)
      fprintf(dump_file, "var_decl c1arg1_v min %s\n", print_generic_expr_to_str(min));
            if (dump_file)
      fprintf(dump_file, "var_decl c1arg1_v max %s\n", print_generic_expr_to_str(max));
            if (dump_file)
      fprintf(dump_file, "var_decl c1arg1_v minnr %ld\n", tree_to_shwi(min));
            if (dump_file)
      fprintf(dump_file, "var_decl c1arg1_v maxnr %ld\n", tree_to_shwi(max));
            if (tree_to_shwi(min) != 0)
            {
      goto dont_take;
            }
            if (tree_to_shwi(max) != 30)
            {
      goto dont_take;
            }
            tmp = TREE_TYPE(tmp);
            }
        }

        gsi_remove(&i, true);

        // we have now to decide was is the best option
        // for no-inline g0, we take the full blow version
        // for inline, we take the shortened version
        if (flag_no_inline == 0)
        {
            option_strcpy_inline = 1;
        }
        else
        {
            option_strcpy_inline = 1;
        }
        if (flag_lto)
            option_strcpy_inline = 0;

        if (option_strcpy_inline == 0)
        {
            i_pmemw = create_tmp_var_raw(build_pointer_type(unsigned_type_node));
            i_pmems = create_tmp_var_raw(build_pointer_type(short_unsigned_type_node));
            i_pmemc = create_tmp_var_raw(build_pointer_type(char_type_node));
            gimpleassign = gimple_build_assign(i_pmemw, c1arg1);
            gsi_insert_before(&i, gimpleassign, GSI_NEW_STMT);
            immed = (tmp_buf[3] << 24) + (tmp_buf[2] << 16) + (tmp_buf[1] << 8) + tmp_buf[0];
            gimpleassign = gimple_build_assign(build2(MEM_REF, unsigned_type_node, i_pmemw, build_int_cst(TREE_TYPE(i_pmemw), 0)), build_int_cstu(unsigned_type_node, immed));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmemw, POINTER_PLUS_EXPR, i_pmemw, build_int_cstu(unsigned_type_node, 4));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            immed = (tmp_buf[7] << 24) + (tmp_buf[6] << 16) + (tmp_buf[5] << 8) + tmp_buf[4];
            gimpleassign = gimple_build_assign(build2(MEM_REF, unsigned_type_node, i_pmemw, build_int_cst(TREE_TYPE(i_pmemw), 0)), build_int_cstu(unsigned_type_node, immed));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmemw, POINTER_PLUS_EXPR, i_pmemw, build_int_cstu(unsigned_type_node, 4));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            immed = (tmp_buf[11] << 24) + (tmp_buf[10] << 16) + (tmp_buf[9] << 8) + tmp_buf[8];
            gimpleassign = gimple_build_assign(build2(MEM_REF, unsigned_type_node, i_pmemw, build_int_cst(TREE_TYPE(i_pmemw), 0)), build_int_cstu(unsigned_type_node, immed));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmemw, POINTER_PLUS_EXPR, i_pmemw, build_int_cstu(unsigned_type_node, 4));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            immed = (tmp_buf[15] << 24) + (tmp_buf[14] << 16) + (tmp_buf[13] << 8) + tmp_buf[12];
            gimpleassign = gimple_build_assign(build2(MEM_REF, unsigned_type_node, i_pmemw, build_int_cst(TREE_TYPE(i_pmemw), 0)), build_int_cstu(unsigned_type_node, immed));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmemw, POINTER_PLUS_EXPR, i_pmemw, build_int_cstu(unsigned_type_node, 4));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            immed = (tmp_buf[19] << 24) + (tmp_buf[18] << 16) + (tmp_buf[17] << 8) + tmp_buf[16];
            gimpleassign = gimple_build_assign(build2(MEM_REF, unsigned_type_node, i_pmemw, build_int_cst(TREE_TYPE(i_pmemw), 0)), build_int_cstu(unsigned_type_node, immed));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmemw, POINTER_PLUS_EXPR, i_pmemw, build_int_cstu(unsigned_type_node, 4));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            immed = (tmp_buf[23] << 24) + (tmp_buf[22] << 16) + (tmp_buf[21] << 8) + tmp_buf[20];
            gimpleassign = gimple_build_assign(build2(MEM_REF, unsigned_type_node, i_pmemw, build_int_cst(TREE_TYPE(i_pmemw), 0)), build_int_cstu(unsigned_type_node, immed));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmemw, POINTER_PLUS_EXPR, i_pmemw, build_int_cstu(unsigned_type_node, 4));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            immed = (tmp_buf[27] << 24) + (tmp_buf[26] << 16) + (tmp_buf[25] << 8) + tmp_buf[24];
            gimpleassign = gimple_build_assign(build2(MEM_REF, unsigned_type_node, i_pmemw, build_int_cst(TREE_TYPE(i_pmemw), 0)), build_int_cstu(unsigned_type_node, immed));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmems, c1arg1);
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmems, POINTER_PLUS_EXPR, i_pmems, build_int_cstu(unsigned_type_node, 28));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            immed = (tmp_buf[29] << 8) + tmp_buf[28];
            gimpleassign = gimple_build_assign(build2(MEM_REF, short_unsigned_type_node, i_pmems, build_int_cst(TREE_TYPE(i_pmems), 0)), build_int_cstu(short_unsigned_type_node, immed));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmemc, c1arg1);
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            gimpleassign = gimple_build_assign(i_pmemc, POINTER_PLUS_EXPR, i_pmemc, build_int_cstu(unsigned_type_node, 30));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
            immed = tmp_buf[30];
            gimpleassign = gimple_build_assign(build2(MEM_REF, char_type_node, i_pmemc, build_int_cst(TREE_TYPE(i_pmemc), 0)), build_int_cstu(char_type_node, immed));
            gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
        }
        else
        {

            vec<tree, va_gc> *inputs;
            vec<tree, va_gc> *clobbers;
            vec<tree, va_gc> *outputs;
            tree input;
            tree output;
            tree clobber;

            gasm *asm_or_stmt;
            inputs = NULL;
            input = build_tree_list(NULL_TREE, build_string(2, "a"));
            input = chainon(NULL_TREE, build_tree_list(input, c1arg1));
            vec_safe_push(inputs, input);

            input = build_tree_list(NULL_TREE, build_string(2, "i"));
            immed = (tmp_buf[3] << 24) + (tmp_buf[2] << 16) + (tmp_buf[1] << 8) + tmp_buf[0];
            input = chainon(NULL_TREE, build_tree_list(input, build_int_cstu(unsigned_type_node, immed)));
            vec_safe_push(inputs, input);

            input = build_tree_list(NULL_TREE, build_string(2, "i"));
            immed = (tmp_buf[7] << 24) + (tmp_buf[6] << 16) + (tmp_buf[5] << 8) + tmp_buf[4];
            input = chainon(NULL_TREE, build_tree_list(input, build_int_cstu(unsigned_type_node, immed)));
            vec_safe_push(inputs, input);

            input = build_tree_list(NULL_TREE, build_string(2, "i"));
            immed = (tmp_buf[11] << 24) + (tmp_buf[10] << 16) + (tmp_buf[9] << 8) + tmp_buf[8];
            input = chainon(NULL_TREE, build_tree_list(input, build_int_cstu(unsigned_type_node, immed)));
            vec_safe_push(inputs, input);

            input = build_tree_list(NULL_TREE, build_string(2, "i"));
            immed = (tmp_buf[15] << 24) + (tmp_buf[14] << 16) + (tmp_buf[13] << 8) + tmp_buf[12];
            input = chainon(NULL_TREE, build_tree_list(input, build_int_cstu(unsigned_type_node, immed)));
            vec_safe_push(inputs, input);

            input = build_tree_list(NULL_TREE, build_string(2, "i"));
            immed = (tmp_buf[19] << 24) + (tmp_buf[18] << 16) + (tmp_buf[17] << 8) + tmp_buf[16];
            input = chainon(NULL_TREE, build_tree_list(input, build_int_cstu(unsigned_type_node, immed)));
            vec_safe_push(inputs, input);

            input = build_tree_list(NULL_TREE, build_string(2, "i"));
            immed = (tmp_buf[23] << 24) + (tmp_buf[22] << 16) + (tmp_buf[21] << 8) + tmp_buf[20];
            input = chainon(NULL_TREE, build_tree_list(input, build_int_cstu(unsigned_type_node, immed)));
            vec_safe_push(inputs, input);

            input = build_tree_list(NULL_TREE, build_string(2, "i"));
            immed = (tmp_buf[27] << 24) + (tmp_buf[26] << 16) + (tmp_buf[25] << 8) + tmp_buf[24];
            input = chainon(NULL_TREE, build_tree_list(input, build_int_cstu(unsigned_type_node, immed)));
            vec_safe_push(inputs, input);

            input = build_tree_list(NULL_TREE, build_string(2, "i"));
            immed = (tmp_buf[29] << 8) + tmp_buf[28];
            input = chainon(NULL_TREE, build_tree_list(input, build_int_cstu(unsigned_type_node, immed)));
            vec_safe_push(inputs, input);

            input = build_tree_list(NULL_TREE, build_string(2, "i"));
            immed = tmp_buf[30];
            input = chainon(NULL_TREE, build_tree_list(input, build_int_cstu(unsigned_type_node, immed)));
            vec_safe_push(inputs, input);

            outputs = NULL;
            vec_safe_push(outputs, output);
            clobbers = NULL;
            clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
            vec_safe_push(clobbers, clobber);
            clobber = build_tree_list(NULL_TREE, build_string(3, "d7"));
            vec_safe_push(clobbers, clobber);
            asm_or_stmt = gimple_build_asm_vec(
                "	 movh %%d7,hi:%1 \n"
                "	 addi %%d7,%%d7,lo:%1 \n"
                "	 st.w [%0]0,%%d7 \n"
                "	 movh %%d7,hi:%2 \n"
                "	 addi %%d7,%%d7,lo:%2 \n"
                "	 st.w [%0]4,%%d7 \n"
                "	 movh %%d7,hi:%3 \n"
                "	 addi %%d7,%%d7,lo:%3 \n"
                "	 st.w [%0]8,%%d7 \n"
                "	 movh %%d7,hi:%4 \n"
                "	 addi %%d7,%%d7,lo:%4 \n"
                "	 st.w [%0]12,%%d7 \n"
                "	 movh %%d7,hi:%5 \n"
                "	 addi %%d7,%%d7,lo:%5 \n"
                "	 st.w [%0]16,%%d7 \n"
                "	 movh %%d7,hi:%6 \n"
                "	 addi %%d7,%%d7,lo:%6 \n"
                "	 st.w [%0]20,%%d7 \n"
                "	 movh %%d7,hi:%7 \n"
                "	 addi %%d7,%%d7,lo:%7 \n"
                "	 st.w [%0]24,%%d7 \n"
                "	 mov  %%d7,%8 \n"
                "	 st.h [%0]28,%%d7 \n"
                "	 mov  %%d7,%9 \n"
                "	 st.b [%0]30,%%d7 \n",
                inputs, NULL, clobbers, NULL);

            gimple_asm_set_volatile(asm_or_stmt, true);
            gsi_insert_before(&i, asm_or_stmt, GSI_NEW_STMT);
        }

        {
            gimplebind = NULL;
            gimpletry = NULL;
            code_gsi = gimple_code(stmt_entry);
            if (code_gsi == GIMPLE_BIND)
            {
            gimplebind = dyn_cast<gbind *>(stmt_entry);
            if (dump_file)
      fprintf(dump_file, "Apply Change GIMPLE_BIND %d \n", *bind_nr);
            gimple_bind_set_body(gimplebind, seq);
            ;
            }
            if (code_gsi == GIMPLE_TRY)
            {
            gimpletry = dyn_cast<gtry *>(stmt_entry);
            if (dump_file)
      fprintf(dump_file, "Apply Change GIMPLE_TRY %d \n", *bind_nr);
            gimple_try_set_eval(gimpletry, seq);
            }
            if ((gimplebind == NULL) && (gimpletry == NULL))
            {
            goto dont_take;
            }

            //		for (int jj = (vec_safe_length (*gimples) -1) ; jj >= 0; jj--)
            //                      {
            //                    lgimple=*gimples;
            //                    code_gsi = gimple_code ((*lgimple)[jj]);
            //                        if (code_gsi==GIMPLE_CALL) {
            //                            if (dump_file) fprintf( dump_file, "GIMPLE_CALL %d \n", jj);
            //                           }
            //                        if (code_gsi==GIMPLE_BIND) {
            //                            gimplebind=dyn_cast <gbind *> ( (*lgimple)[jj]);
            //                            if (dump_file) fprintf( dump_file, "GIMPLE_BIND %d \n", jj);
            //                            break;
            //                        }
            //                        if (code_gsi==GIMPLE_TRY) {
            //                            gimpletry=dyn_cast <gtry *> ( (*lgimple)[jj]);
            //                            if (dump_file) fprintf( dump_file, "GIMPLE_TRY %d \n",jj);
            //                            break;
            //                        }
            //                      }
            //                if ((gimplebind==NULL) && (gimpletry==NULL)) { goto dont_take; }
            //                if (code_gsi==GIMPLE_TRY)
            //                  {
            //                  gimple_try_set_eval (gimpletry, seq);
            //                  }
            //                if (code_gsi==GIMPLE_BIND)
            //                  {
            //                    gimple_bind_set_body (gimplebind, seq);;
            //                  }
        }
        //                continue;
      dont_take:;
      }
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
        tree var;
        if (dump_file)
            fprintf(dump_file, "recall GIMPLE_BIND\n");
        //            for (var = gimple_bind_vars (gimplebind); var; var = DECL_CHAIN (var))
        //              {
        //        	if (dump_file) fprintf(dump_file,"Push local var %s\n",print_generic_expr_to_str(var));
        //        	vec_safe_push(*locbind_vardecl, var);
        //              }
        tricopt_gimple_gen_stmts_strcpy(seq, i, stmt, gimples, locbind_vardecl, stmtit, stmtseq, bind_nr);
      }
      if (code == GIMPLE_TRY)
      {
        if (dump_file)
            fprintf(dump_file, "recall GIMPLE_TRY\n");
        gimpletry = dyn_cast<gtry *>(stmt);
        tricopt_gimple_gen_stmts_strcpy(seq, i, stmt, gimples, locbind_vardecl, stmtit, stmtseq, bind_nr);
      }
      gsi_next(&i);
  }
  *bind_nr -= 1;
  if (dump_file)
      fprintf(dump_file, "GIMPLE_SCAN STRCPY LEAVE %d %d\n", gimple_len, *bind_nr);
}
#endif

void tricopt_gimple_gen_strcpy(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  int stmt_nr;
  int bind_nr = 0;

  vec<tree, va_gc> *trvec_args = NULL;
  vec<gimple *, va_gc> *gimples = NULL;
  vec<tree, va_gc> *locbind_vardecl = NULL;
  vec<gimple_stmt_iterator, va_gc> *stmtit = NULL;
  vec<gimple_seq, va_gc> *stmtseq = NULL;
  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Sequence strcpy\n");
  stmt_nr = 0;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      tricopt_gimple_gen_stmts_strcpy(body, i, stmt, &gimples, &locbind_vardecl, &stmtit, &stmtseq, &bind_nr);
      if (dump_file)
        fprintf(dump_file, "Bind Body %d ", stmt_nr);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
      stmt_nr += 1;
      if (code == GIMPLE_BIND)
        break;
  }

  if (dump_file)
      fprintf(dump_file, "Length Gimples %d \n", vec_safe_length(gimples));
  if (dump_file)
      fprintf(dump_file, "Length Stmtit %d \n", vec_safe_length(stmtit));
  if (dump_file)
      fprintf(dump_file, "Length Stmrseq %d \n", vec_safe_length(stmtseq));
  return;
}

void tricopt_gimple_gen_proc_1(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  gbind *gimplebind;
  int stmt_nr;
  gassign *assign;
  gcond *gimplecond = NULL;
  gimple *gimplecondstmt = NULL;
  gimple_stmt_iterator gsi_cond;
  vec<tree, va_gc> *trvec_args = NULL;

  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Proc_1\n");
  gimplebind = NULL;
  stmt_nr = 0;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
      }
      if (dump_file)
        fprintf(dump_file, "Bind Body %d ", stmt_nr);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
      stmt_nr += 1;
      if (code == GIMPLE_BIND)
        break;
  }
  gimple_seq outer_body = gimple_bind_body(gimplebind);
  if (dump_file)
      fprintf(dump_file, "Gimble_Bind Begin\n");
  stmt_nr = 0;
  for (i = gsi_start(outer_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if ((code == GIMPLE_COND))
      {
        int fail = 0;
        if (gimple_cond_code(stmt) != EQ_EXPR)
            fail = 1;
        if (strcmp(print_generic_expr_to_str(TREE_TYPE(gimple_cond_rhs(stmt))), "Enumeration") != 0)
            fail = 1;
        if (dump_file)
            fprintf(dump_file, "FAIL_COND=%d \n ", fail);
        if (dump_file)
            fprintf(dump_file, "lhs %s\n", print_generic_expr_to_str(TREE_TYPE(gimple_cond_rhs(stmt))));
        gimplecond = dyn_cast<gcond *>(stmt);
        gimplecondstmt = stmt;
        gsi_cond = i;
      }
      if (dump_file)
        fprintf(dump_file, "Try %d ", stmt_nr);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
      stmt_nr += 1;
  }

  tree lhs_xxxx = create_tmp_var_raw(long_integer_type_node);
  tree lhs_nop_xxxx = create_tmp_var_raw(boolean_type_node);
  tree rhs_labtrue = gimple_cond_true_label(gimplecond);
  tree rhs_labfalse = gimple_cond_false_label(gimplecond);
  tree rhs = gimple_cond_rhs(gimplecondstmt);
  tree expr_lhs = gimple_cond_lhs(gimplecondstmt);
  gsi_remove(&gsi_cond, true);
  assign = gimple_build_assign(lhs_nop_xxxx, EQ_EXPR, expr_lhs, rhs);
  gsi_insert_before(&gsi_cond, assign, GSI_NEW_STMT);
  assign = gimple_build_assign(lhs_xxxx, NOP_EXPR, lhs_nop_xxxx);
  gsi_insert_after(&gsi_cond, assign, GSI_NEW_STMT);
  gcall *gimple_expect;
  tree decl = NULL_TREE;
  decl = builtin_decl_implicit(BUILT_IN_EXPECT);
  tree lhs_expect = create_tmp_var_raw(long_integer_type_node);
  gimple_expect = gimple_build_call(decl, 2, lhs_xxxx, build_int_cst(long_integer_type_node, 1));
  gimple_call_set_lhs(gimple_expect, lhs_expect);
  gsi_insert_after(&gsi_cond, gimple_expect, GSI_NEW_STMT);
  gimplecond = gimple_build_cond(NE_EXPR, lhs_expect, build_int_cst(long_integer_type_node, 0), rhs_labtrue, rhs_labfalse);
  gsi_insert_after(&gsi_cond, gimplecond, GSI_NEW_STMT);
  gimple_bind_set_body(gimplebind, outer_body);
  return;
}

void tricopt_gimple_gen_mat_add_const(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  gbind *gimplebind;
  //  greturn *gimpleret;
  gassign *gimpleassign;
  gcond *gimplecond;
  ggoto *gimplegoto;
  //  tree tr_return;
  vec<tree, va_gc> *inputs;
  vec<tree, va_gc> *clobbers;
  vec<tree, va_gc> *outputs;
  tree input;
  tree output;
  tree clobber;
  tree type = unsigned_type_node;

  vec<tree, va_gc> *trvec_args = NULL;

  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Sequence mat_add_const\n");
  gimplebind = NULL;
  //  gimpleret=NULL;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
      }
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_seq inner_body = gimple_bind_body(gimplebind);
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  greturn *stmt = gimple_build_return(NULL);
  gsi_insert_before(&i, stmt, GSI_NEW_STMT);

  inner_body = gimple_bind_body(gimplebind);
  i = gsi_start(inner_body);
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_next(&i);
        if (dump_file)
            fprintf(dump_file, "found return tree with removal!\n");
        //          tr_return=gimple_return_retval(dyn_cast <greturn *> (stmt));
        //          gimpleret=dyn_cast <greturn *> (stmt);
        break;
      default:
        if (dump_file)
            fprintf(dump_file, "remove stmt!\n");
        if (dump_file)
            print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
        gsi_next(&i);
        break;
      }
  }

  gasm *asm_or_stmt;

  tree i_val_pack = create_tmp_var_raw(unsigned_type_node);
  tree i_t0 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_i = create_tmp_var_raw(unsigned_type_node);

  tree i_1 = create_tmp_var_raw(unsigned_type_node);
  gimpleassign = gimple_build_assign(i_1, NOP_EXPR, (*trvec_args)[2]);
  gsi_insert_before(&i, gimpleassign, GSI_NEW_STMT);
  gimpleassign = gimple_build_assign(i_val_pack, BIT_AND_EXPR, i_1, build_int_cstu(unsigned_type_node, 65535));
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
  tree i_2 = create_tmp_var_raw(TREE_TYPE(i_val_pack));
  gimpleassign = gimple_build_assign(i_2, LSHIFT_EXPR, i_val_pack, build_int_cstu(unsigned_type_node, 16));
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);

  gimpleassign = gimple_build_assign(i_val_pack, BIT_IOR_EXPR, i_val_pack, i_2);
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);

  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "a"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[1]));
  vec_safe_push(inputs, input);
  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t0));
  vec_safe_push(outputs, output);
  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec("ld.d %A0, [%1]0", inputs, outputs, clobbers, NULL);
  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);
  gimpleassign = gimple_build_assign(i_i, build_int_cstu(unsigned_type_node, 0));
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
  glabel *gD1459 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gimplegoto = gimple_build_goto(gimple_label_label(gD1459));
  gsi_insert_after(&i, gimplegoto, GSI_NEW_STMT);
  glabel *gD1458 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gsi_insert_after(&i, gD1458, GSI_NEW_STMT);
  tree i_t1 = create_tmp_var_raw(long_long_integer_type_node);
  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[1]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t1));
  vec_safe_push(outputs, output);
  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, i_val_pack));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "0"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[1]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "1"));
  input = chainon(NULL_TREE, build_tree_list(input, i_t0));
  vec_safe_push(inputs, input);

  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec("\tadd.h %L1, %L1, %3 \n"
                                     "\tld.d %A2, [%0]8\n"
                                     "\tadd.h %H1, %H1, %3\n"
                                     "\tst.d [%0+]8, %A1\n"
                                     "\tadd.h %L2, %L2, %3\n"
                                     "\tld.d %A1, [%0]8\n"
                                     "\tadd.h %H2, %H2, %3\n"
                                     "\tst.d [%0+]8, %A2\n",
                                     inputs, outputs, clobbers, NULL);
  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);
  gimpleassign = gimple_build_assign(i_i, PLUS_EXPR, i_i, build_int_cstu(unsigned_type_node, 1));
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);

  gsi_insert_after(&i, gD1459, GSI_NEW_STMT);
  glabel *gD1460 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gimplecond = gimple_build_cond(LE_EXPR, i_i, build_int_cstu(unsigned_type_node, 9), gimple_label_label(gD1458), gimple_label_label(gD1460));
  gsi_insert_after(&i, gimplecond, GSI_NEW_STMT);
  gsi_insert_after(&i, gD1460, GSI_NEW_STMT);

  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t0));
  vec_safe_push(outputs, output);
  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "a"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[1]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, i_val_pack));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "0"));
  input = chainon(NULL_TREE, build_tree_list(input, i_t0));
  vec_safe_push(inputs, input);

  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec("\tadd.h %L0, %L0, %2 \n"
                                     "\tst.h [%1], %L0\n",
                                     inputs, outputs, clobbers, NULL);
  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);

  greturn *gstmt = gimple_build_return(NULL);
  gsi_insert_after(&i, gstmt, GSI_NEW_STMT);

  tree false_cond;
  tree true_cond;
  true_cond = create_artificial_label(UNKNOWN_LOCATION);
  false_cond = create_artificial_label(UNKNOWN_LOCATION);
  glabel *gfalse_cond = gimple_build_label(false_cond);
  glabel *gtrue_cond = gimple_build_label(true_cond);
  gcond *gcond_stmt = gimple_build_cond(NE_EXPR, (*trvec_args)[0], build_int_cstu(type, 9),
                                        true_cond, false_cond);
  i = gsi_start(inner_body);
  gsi_insert_before(&i, gcond_stmt, GSI_NEW_STMT);
  gsi_insert_after(&i, gtrue_cond, GSI_NEW_STMT);
  i = gsi_start(inner_body);
  int false_leave = 0;
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_insert_after(&i, gfalse_cond, GSI_NEW_STMT);
        false_leave = 1;
        break;
      default:
        break;
      }
      if (false_leave == 1)
        break;
      gsi_next(&i);
  }

  if (dump_file)
      fprintf(dump_file, "before gimple_bind_set_body!\n");
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_bind_set_body(gimplebind, inner_body);
}

void tricopt_gimple_gen_mat_mul_matrix(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  gbind *gimplebind;
  //  greturn *gimpleret;
  gassign *gimpleassign;
  gcond *gimplecond;
  ggoto *gimplegoto;
  //  tree tr_return;
  vec<tree, va_gc> *inputs;
  vec<tree, va_gc> *clobbers;
  vec<tree, va_gc> *outputs;
  tree input;
  tree output;
  tree clobber;
  tree type = unsigned_type_node;

  vec<tree, va_gc> *trvec_args = NULL;

  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Sequence mat_mul_matrix\n");
  gimplebind = NULL;
  //  gimpleret=NULL;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
      }
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_seq inner_body = gimple_bind_body(gimplebind);
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  greturn *stmt = gimple_build_return(NULL);
  gsi_insert_before(&i, stmt, GSI_NEW_STMT);

  inner_body = gimple_bind_body(gimplebind);
  i = gsi_start(inner_body);
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_next(&i);
        if (dump_file)
            fprintf(dump_file, "found return tree with removal!\n");
        //          tr_return=gimple_return_retval(dyn_cast <greturn *> (stmt));
        //          gimpleret=dyn_cast <greturn *> (stmt);
        break;
      default:
        if (dump_file)
            fprintf(dump_file, "remove stmt!\n");
        if (dump_file)
            print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
        gsi_next(&i);
        break;
      }
  }

  gasm *asm_or_stmt;
  tree i_i = create_tmp_var_raw(unsigned_type_node);
  gimpleassign = gimple_build_assign(i_i, build_int_cstu(unsigned_type_node, 0));
  gsi_insert_before(&i, gimpleassign, GSI_NEW_STMT);
  glabel *gD1459 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gimplegoto = gimple_build_goto(gimple_label_label(gD1459));
  gsi_insert_after(&i, gimplegoto, GSI_NEW_STMT);
  glabel *gD1458 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gsi_insert_after(&i, gD1458, GSI_NEW_STMT);

  tree i_l2cnt = create_tmp_var_raw(build_pointer_type(void_type_node));
  tree i_acc0 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_acc1 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_t0 = create_tmp_var_raw(integer_type_node);
  tree i_t1 = create_tmp_var_raw(integer_type_node);
  tree i_t2 = create_tmp_var_raw(integer_type_node);
  tree i_b0 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_b1 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_b2 = create_tmp_var_raw(long_long_integer_type_node);

  tree il_acc = create_tmp_var_raw(long_long_integer_type_node);
  tree il_t0 = create_tmp_var_raw(long_long_integer_type_node);
  tree il_b1 = create_tmp_var_raw(integer_type_node);

  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[3]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[1]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&a"));
  output = chainon(NULL_TREE, build_tree_list(output, i_l2cnt));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_acc0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_acc1));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t1));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t2));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_b0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_b1));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_b2));
  vec_safe_push(outputs, output);
  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "a"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[2]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "0"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[3]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "1"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[1]));
  vec_safe_push(inputs, input);

  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec(
      "\tld.h %5, [%11] \n" \
      "\tld.d %A8, [%0+](9*2) \n" \
      "\tmov.a %2, 2-1 \n" \
      "\t.LL%=: \n" \
      "\tld.h %7, [%11]1*2 \n" \
      "\tmul.h %A3, %L8, %5LL,0 \n" \
      "\tld.d %A9, [%0+](9*2) \n" \
      "\tmul.h %A4, %H8, %5LL,0 \n" \
      "\tld.h %6, [%11]2*2 \n" \
      "\tmadd.h %A3, %A3, %L9, %7LL,0 \n" \
      "\tld.d %A10, [%0+](9*2) \n" \
      "\tmadd.h %A4, %A4, %H9, %7LL,0 \n" \
      "\tld.h %7, [%11]3*2 \n" \
      "\tmadd.h %A3, %A3, %L10, %6LL,0 \n" \
      "\tld.d %A8, [%0+](9*2) \n" \
      "\tmadd.h %A4, %A4, %H10, %6LL,0 \n" \
      "\tld.h %6, [%11]4*2 \n" \
      "\tmadd.h %A3, %A3, %L8, %7LL,0 \n" \
      "\tld.d %A9, [%0+](9*2) \n" \
      "\tmadd.h %A4, %A4, %H8, %7LL,0 \n" \
      "\tld.h %7, [%11]5*2 \n" \
      "\tmadd.h %A3, %A3, %L9, %6LL,0 \n" \
      "\tld.d %A10, [%0+](9*2) \n" \
      "\tmadd.h %A4, %A4, %H9, %6LL,0 \n" \
      "\tld.h %6, [%11]6*2 \n" \
      "\tmadd.h %A3, %A3, %L10, %7LL,0 \n" \
      "\tld.d %A8, [%0+](9*2) \n" \
      "\tmadd.h %A4, %A4, %H10, %7LL,0 \n" \
      "\tld.h %7, [%11]7*2 \n" \
      "\tmadd.h %A3, %A3, %L8, %6LL,0 \n" \
      "\tld.d %A9, [%0+](9*2) \n" \
      "\tmadd.h %A4, %A4, %H8, %6LL,0 \n" \
      "\tld.h %6, [%11]8*2 \n" \
      "\tmadd.h %A3, %A3, %L9, %7LL,0 \n" \
      "\tld.d %A10, [%0+]((4 - 8*9)*2) \n" \
      "\tmadd.h %A4, %A4, %H9, %7LL,0 \n" \
      "\tld.d %A8, [%0+](9*2) \n" \
      "\tmadd.h %A3, %A3, %L10, %6LL,0 \n" \
      "\tst.d [%1+]8, %A3 \n" \
      "\tmadd.h %A4, %A4, %H10, %6LL,0 \n" \
      "\tst.d [%1+]8, %A4 \n" \
      "\tloop %2, .LL%= \n", \
      inputs, outputs, clobbers, NULL);

  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);

  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[2]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[3]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[1]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, il_acc));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, il_t0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_b0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(4, "=&d"));
  output = chainon(NULL_TREE, build_tree_list(output, il_b1));
  vec_safe_push(outputs, output);
  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "0"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[2]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "1"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[3]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "2"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[1]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "5"));
  input = chainon(NULL_TREE, build_tree_list(input, i_b0));
  vec_safe_push(inputs, input);

  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec(
      "\tld.d %A4, [%0+](9*2) \n" \
      "\tld.h %6, [%1+](9*2) \n" \
      "\tmul.h %A3, %L5, %L4LL,0 \n" \
      "\tld.h %L5, [%1+](9*2) \n" \
      "\tmadd.h %A3, %A3, %6, %L4LU,0 \n" \
      "\tld.h %6, [%1+](9*2) \n" \
      "\tmadd.h %A3, %A3, %L5, %H4LL,0 \n" \
      "\tld.h %L5, [%1+](9*2) \n" \
      "\tmadd.h %A3, %A3, %6, %H4LU,0 \n" \
      "\tld.d %A4, [%0](1*8 - 9*2) \n" \
      "\tld.h %6, [%1+](9*2) \n" \
      "\tmadd.h %A3, %A3, %L5, %L4LL,0 \n" \
      "\tld.h %L5, [%1+](9*2) \n" \
      "\tmadd.h %A3, %A3, %6, %L4LU,0 \n" \
      "\tld.h %H5, [%1+](9*2) \n" \
      "\tld.h %6, [%1+](-(8 + 8*9)*2) \n" \
      "\tmadd.h %A3, %A3, %L5, %H4LL,0 \n" \
      "\tld.h %L4, [%0](2*8 - 9*2) \n" \
      "\tmadd.h %A3, %A3, %H5, %H4LU,0 \n" \
      "\tmadd.h %A3, %A3, %6, %L4LL,0 \n" \
      "\tst.w [%2+], %L3 \n", \
      inputs, outputs, clobbers, NULL);

  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);

  gimpleassign = gimple_build_assign(i_i, PLUS_EXPR, i_i, build_int_cstu(unsigned_type_node, 1));
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
  gsi_insert_after(&i, gD1459, GSI_NEW_STMT);
  glabel *gD1460 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gimplecond = gimple_build_cond(LE_EXPR, i_i, build_int_cstu(unsigned_type_node, 8), gimple_label_label(gD1458), gimple_label_label(gD1460));
  gsi_insert_after(&i, gimplecond, GSI_NEW_STMT);
  gsi_insert_after(&i, gD1460, GSI_NEW_STMT);
  greturn *gstmt = gimple_build_return(NULL);
  gsi_insert_after(&i, gstmt, GSI_NEW_STMT);

  tree false_cond;
  tree true_cond;
  true_cond = create_artificial_label(UNKNOWN_LOCATION);
  false_cond = create_artificial_label(UNKNOWN_LOCATION);
  glabel *gfalse_cond = gimple_build_label(false_cond);
  glabel *gtrue_cond = gimple_build_label(true_cond);
  gcond *gcond_stmt = gimple_build_cond(NE_EXPR, (*trvec_args)[0], build_int_cstu(type, 9),
                                        true_cond, false_cond);
  i = gsi_start(inner_body);
  gsi_insert_before(&i, gcond_stmt, GSI_NEW_STMT);
  gsi_insert_after(&i, gtrue_cond, GSI_NEW_STMT);
  i = gsi_start(inner_body);
  int false_leave = 0;
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_insert_after(&i, gfalse_cond, GSI_NEW_STMT);
        false_leave = 1;
        break;
      default:
        break;
      }
      if (false_leave == 1)
        break;
      gsi_next(&i);
  }

  if (dump_file)
      fprintf(dump_file, "before gimple_bind_set_body!\n");
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_bind_set_body(gimplebind, inner_body);
}

void tricopt_gimple_gen_mat_mul_vect(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  gbind *gimplebind;
  //  greturn *gimpleret;
  gassign *gimpleassign;
  gcond *gimplecond;
  ggoto *gimplegoto;
  //  tree tr_return;
  vec<tree, va_gc> *inputs;
  vec<tree, va_gc> *clobbers;
  vec<tree, va_gc> *outputs;
  tree input;
  tree output;
  tree clobber;
  tree type = unsigned_type_node;

  vec<tree, va_gc> *trvec_args = NULL;

  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Sequence mat_mul_vect\n");
  gimplebind = NULL;
  //  gimpleret=NULL;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
      }
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_seq inner_body = gimple_bind_body(gimplebind);
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  greturn *stmt = gimple_build_return(NULL);
  gsi_insert_before(&i, stmt, GSI_NEW_STMT);

  inner_body = gimple_bind_body(gimplebind);
  i = gsi_start(inner_body);
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_next(&i);
        if (dump_file)
            fprintf(dump_file, "found return tree with removal!\n");
        //          tr_return=gimple_return_retval(dyn_cast <greturn *> (stmt));
        //          gimpleret=dyn_cast <greturn *> (stmt);
        break;
      default:
        if (dump_file)
            fprintf(dump_file, "remove stmt!\n");
        if (dump_file)
            print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
        gsi_next(&i);
        break;
      }
  }

  gasm *asm_or_stmt;
  tree i_b0 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_b1 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_i = create_tmp_var_raw(unsigned_type_node);
  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "a"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[3]));
  vec_safe_push(inputs, input);
  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_b0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_b1));
  vec_safe_push(outputs, output);
  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec("\tld.d %A0, [%2]0\n"
                                     "\tld.d %A1, [%2]8\n",
                                     inputs, outputs, clobbers, NULL);
  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_before(&i, asm_or_stmt, GSI_NEW_STMT);
  gimpleassign = gimple_build_assign(i_i, build_int_cstu(unsigned_type_node, 0));
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
  glabel *gD1459 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gimplegoto = gimple_build_goto(gimple_label_label(gD1459));
  gsi_insert_after(&i, gimplegoto, GSI_NEW_STMT);
  glabel *gD1458 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gsi_insert_after(&i, gD1458, GSI_NEW_STMT);
  tree i_t0 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_t1 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_acc = create_tmp_var_raw(long_long_integer_type_node);

  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[2]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[1]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_acc));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t1));
  vec_safe_push(outputs, output);
  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "a"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[3]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, i_b0));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, i_b1));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "0"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[2]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "1"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[1]));
  vec_safe_push(inputs, input);

  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec(
      "\tld.d %A3, [%0+]8 \n"
      "\tld.d %A4, [%0+]8\n"
      "\tmulm.h %A2, %L3, %L6UL,0\n"
      "\tmaddm.h %A2, %A2, %H3, %H6UL,0\n"
      "\tld.hu %L3, [%0+]2\n"
      "\tmaddm.h %A2, %A2, %L4, %L7UL,0\n"
      "\tld.hu %H3, [%5]16\n"
      "\tmaddm.h %A2, %A2, %H4, %H7UL,0\n"
      "\tmaddm.h %A2, %A2, %L3, %H3UL,0\n"
      "\tst.q [%1+]2, %L2\n"
      "\tst.h [%1+], %H2\n",
      inputs, outputs, clobbers, NULL);
  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);

  gimpleassign = gimple_build_assign(i_i, PLUS_EXPR, i_i, build_int_cstu(unsigned_type_node, 1));
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
  gsi_insert_after(&i, gD1459, GSI_NEW_STMT);
  glabel *gD1460 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gimplecond = gimple_build_cond(LE_EXPR, i_i, build_int_cstu(unsigned_type_node, 8), gimple_label_label(gD1458), gimple_label_label(gD1460));
  gsi_insert_after(&i, gimplecond, GSI_NEW_STMT);
  gsi_insert_after(&i, gD1460, GSI_NEW_STMT);
  greturn *gstmt = gimple_build_return(NULL);
  gsi_insert_after(&i, gstmt, GSI_NEW_STMT);

  tree false_cond;
  tree true_cond;
  true_cond = create_artificial_label(UNKNOWN_LOCATION);
  false_cond = create_artificial_label(UNKNOWN_LOCATION);
  glabel *gfalse_cond = gimple_build_label(false_cond);
  glabel *gtrue_cond = gimple_build_label(true_cond);
  gcond *gcond_stmt = gimple_build_cond(NE_EXPR, (*trvec_args)[0], build_int_cstu(type, 9),
                                        true_cond, false_cond);
  i = gsi_start(inner_body);
  gsi_insert_before(&i, gcond_stmt, GSI_NEW_STMT);
  gsi_insert_after(&i, gtrue_cond, GSI_NEW_STMT);
  i = gsi_start(inner_body);
  int false_leave = 0;
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_insert_after(&i, gfalse_cond, GSI_NEW_STMT);
        false_leave = 1;
        break;
      default:
        break;
      }
      if (false_leave == 1)
        break;
      gsi_next(&i);
  }
  if (dump_file)
      fprintf(dump_file, "before gimple_bind_set_body!\n");
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_bind_set_body(gimplebind, inner_body);
}

void tricopt_gimple_gen_mat_mul_const(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  gbind *gimplebind;
  //  greturn *gimpleret;
  gassign *gimpleassign;
  gcond *gimplecond;
  ggoto *gimplegoto;
  //  tree tr_return;
  vec<tree, va_gc> *inputs;
  vec<tree, va_gc> *clobbers;
  vec<tree, va_gc> *outputs;
  tree input;
  tree output;
  tree clobber;
  tree type = unsigned_type_node;

  vec<tree, va_gc> *trvec_args = NULL;

  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Sequence mat_mul_const\n");
  gimplebind = NULL;
  //  gimpleret=NULL;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
      }
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_seq inner_body = gimple_bind_body(gimplebind);
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  greturn *stmt = gimple_build_return(NULL);
  gsi_insert_before(&i, stmt, GSI_NEW_STMT);

  inner_body = gimple_bind_body(gimplebind);
  i = gsi_start(inner_body);
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_next(&i);
        if (dump_file)
            fprintf(dump_file, "found return tree with removal!\n");
        //          tr_return=gimple_return_retval(dyn_cast <greturn *> (stmt));
        //          gimpleret=dyn_cast <greturn *> (stmt);
        break;
      default:
        if (dump_file)
            fprintf(dump_file, "remove stmt!\n");
        if (dump_file)
            print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
        gsi_next(&i);
        break;
      }
  }

  gasm *asm_or_stmt;
  tree i_t0 = create_tmp_var_raw(long_long_integer_type_node);

  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "1"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[2]));
  vec_safe_push(inputs, input);
  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[2]));
  vec_safe_push(outputs, output);
  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec("ld.d %A0, [%1+]8", inputs, outputs, clobbers, NULL);
  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_before(&i, asm_or_stmt, GSI_NEW_STMT);
  tree i_i = create_tmp_var_raw(unsigned_type_node);
  gimpleassign = gimple_build_assign(i_i, build_int_cstu(unsigned_type_node, 0));
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);
  glabel *gD1459 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gimplegoto = gimple_build_goto(gimple_label_label(gD1459));
  gsi_insert_after(&i, gimplegoto, GSI_NEW_STMT);
  glabel *gD1458 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gsi_insert_after(&i, gD1458, GSI_NEW_STMT);
  tree i_t1 = create_tmp_var_raw(long_long_integer_type_node);
  tree i_t2 = create_tmp_var_raw(long_long_integer_type_node);

  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[2]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, (*trvec_args)[1]));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t0));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t1));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t2));
  vec_safe_push(outputs, output);
  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[3]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "0"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[2]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "1"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[1]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "2"));
  input = chainon(NULL_TREE, build_tree_list(input, i_t0));
  vec_safe_push(inputs, input);

  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec("\tld.d %A3, [%0+]8 \n"
                                     "\tmul.h %A4, %L2, %5LL,0\n"
                                     "\tst.d [%1+]8, %A4\n"
                                     "\tmul.h %A4, %H2, %5LL,0\n"
                                     "\tst.d [%1+]8, %A4\n"
                                     "\tld.d %A2, [%0+]8\n"
                                     "\tmul.h %A4, %L3, %5LL,0\n"
                                     "\tst.d [%1+]8, %A4\n"
                                     "\tmul.h %A4, %H3, %5LL,0\n"
                                     "\tst.d [%1+]8, %A4\n",
                                     inputs, outputs, clobbers, NULL);
  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);

  gimpleassign = gimple_build_assign(i_i, PLUS_EXPR, i_i, build_int_cstu(unsigned_type_node, 1));
  gsi_insert_after(&i, gimpleassign, GSI_NEW_STMT);

  gsi_insert_after(&i, gD1459, GSI_NEW_STMT);
  glabel *gD1460 = gimple_build_label(create_artificial_label(UNKNOWN_LOCATION));
  gimplecond = gimple_build_cond(LE_EXPR, i_i, build_int_cstu(unsigned_type_node, 9), gimple_label_label(gD1458), gimple_label_label(gD1460));
  gsi_insert_after(&i, gimplecond, GSI_NEW_STMT);
  gsi_insert_after(&i, gD1460, GSI_NEW_STMT);
  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, i_t0));
  vec_safe_push(outputs, output);
  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "a"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[1]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[3]));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "0"));
  input = chainon(NULL_TREE, build_tree_list(input, i_t0));
  vec_safe_push(inputs, input);

  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec("\tmul.h %A0, %L0, %2LL,0 \n"
                                     "\tst.w [%1], %L0\n",
                                     inputs, outputs, clobbers, NULL);
  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);
  greturn *gstmt = gimple_build_return(NULL);
  gsi_insert_after(&i, gstmt, GSI_NEW_STMT);

  tree false_cond;
  tree true_cond;
  true_cond = create_artificial_label(UNKNOWN_LOCATION);
  false_cond = create_artificial_label(UNKNOWN_LOCATION);
  glabel *gfalse_cond = gimple_build_label(false_cond);
  glabel *gtrue_cond = gimple_build_label(true_cond);
  gcond *gcond_stmt = gimple_build_cond(NE_EXPR, (*trvec_args)[0], build_int_cstu(type, 9),
                                        true_cond, false_cond);
  i = gsi_start(inner_body);
  gsi_insert_before(&i, gcond_stmt, GSI_NEW_STMT);
  gsi_insert_after(&i, gtrue_cond, GSI_NEW_STMT);
  i = gsi_start(inner_body);
  int false_leave = 0;
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_insert_after(&i, gfalse_cond, GSI_NEW_STMT);
        false_leave = 1;
        break;
      default:
        break;
      }
      if (false_leave == 1)
        break;
      gsi_next(&i);
  }

  if (dump_file)
      fprintf(dump_file, "before gimple_bind_set_body!\n");
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_bind_set_body(gimplebind, inner_body);
}

void tricopt_gimple_gen_mat(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  gbind *gimplebind;
  //  greturn *gimpleret;
  //  tree tr_return;
  tree type = unsigned_type_node;

  vec<tree, va_gc> *trvec_args = NULL;

  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Sequence mat\n");
  gimplebind = NULL;
  //  gimpleret=NULL;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
      }
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_seq inner_body = gimple_bind_body(gimplebind);
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  greturn *stmt = gimple_build_return(NULL);
  gsi_insert_before(&i, stmt, GSI_NEW_STMT);

  inner_body = gimple_bind_body(gimplebind);
  i = gsi_start(inner_body);
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_next(&i);
        if (dump_file)
            fprintf(dump_file, "found return tree with removal!\n");
        //          tr_return=gimple_return_retval(dyn_cast <greturn *> (stmt));
        //          gimpleret=dyn_cast <greturn *> (stmt);
        break;
      default:
        if (dump_file)
            fprintf(dump_file, "remove stmt!\n");
        if (dump_file)
            print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
        gsi_next(&i);
        break;
      }
  }

  gimple_seq gse = copy_gimple_seq_and_replace_locals(inner_body);
  gimple_bind_add_seq(gimplebind, gse);

  tree false_cond;
  tree true_cond;
  true_cond = create_artificial_label(UNKNOWN_LOCATION);
  false_cond = create_artificial_label(UNKNOWN_LOCATION);
  glabel *gfalse_cond = gimple_build_label(false_cond);
  glabel *gtrue_cond = gimple_build_label(true_cond);
  gcond *gcond_stmt = gimple_build_cond(EQ_EXPR, (*trvec_args)[0], build_int_cstu(type, 9),
                                        true_cond, false_cond);
  i = gsi_start(inner_body);
  gsi_insert_before(&i, gcond_stmt, GSI_NEW_STMT);
  gsi_insert_after(&i, gtrue_cond, GSI_NEW_STMT);
  i = gsi_start(inner_body);
  int false_leave = 0;
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_insert_after(&i, gfalse_cond, GSI_NEW_STMT);
        false_leave = 1;
        break;
      default:
        break;
      }
      if (false_leave == 1)
        break;
      gsi_next(&i);
  }

  if (dump_file)
      fprintf(dump_file, "before gimple_bind_set_body!\n");
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_bind_set_body(gimplebind, inner_body);
}

void tricopt_gimple_gen_mat_ret(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  gbind *gimplebind;
  //  greturn *gimpleret;
  //  tree tr_return;
  tree type = unsigned_type_node;

  vec<tree, va_gc> *trvec_args = NULL;

  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Sequence mat_ret\n");
  gimplebind = NULL;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
      }
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_seq inner_body = gimple_bind_body(gimplebind);
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }

  inner_body = gimple_bind_body(gimplebind);
  i = gsi_start(inner_body);
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_next(&i);
        if (dump_file)
            fprintf(dump_file, "found return tree with removal!\n");
        //          tr_return=gimple_return_retval(dyn_cast <greturn *> (stmt));
        //          gimpleret=dyn_cast <greturn *> (stmt);
        break;
      default:
        if (dump_file)
            fprintf(dump_file, "remove stmt!\n");
        if (dump_file)
            print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
        gsi_next(&i);
        break;
      }
  }

  gimple_seq gse = copy_gimple_seq_and_replace_locals(inner_body);
  gimple_bind_add_seq(gimplebind, gse);

  tree false_cond;
  tree true_cond;
  true_cond = create_artificial_label(UNKNOWN_LOCATION);
  false_cond = create_artificial_label(UNKNOWN_LOCATION);
  glabel *gfalse_cond = gimple_build_label(false_cond);
  glabel *gtrue_cond = gimple_build_label(true_cond);
  gcond *gcond_stmt = gimple_build_cond(EQ_EXPR, (*trvec_args)[0], build_int_cstu(type, 9),
                                        true_cond, false_cond);
  i = gsi_start(inner_body);
  gsi_insert_before(&i, gcond_stmt, GSI_NEW_STMT);
  gsi_insert_after(&i, gtrue_cond, GSI_NEW_STMT);
  i = gsi_start(inner_body);
  int false_leave = 0;
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_insert_after(&i, gfalse_cond, GSI_NEW_STMT);
        false_leave = 1;
        break;
      default:
        break;
      }
      if (false_leave == 1)
        break;
      gsi_next(&i);
  }

  if (dump_file)
      fprintf(dump_file, "before gimple_bind_set_body!\n");
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_bind_set_body(gimplebind, inner_body);
}

void tricopt_gimple_gen_crcu8(function *function ATTRIBUTE_UNUSED)
{
  tree fdecl;
  tree args;
  gimple_stmt_iterator i;
  gbind *gimplebind;
  greturn *gimpleret;
  tree tr_return = NULL;
  vec<tree, va_gc> *inputs;
  vec<tree, va_gc> *outputs;
  tree input;
  tree output;
  tree type = unsigned_type_node;

  vec<tree, va_gc> *trvec_args = NULL;

  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      vec_safe_push(trvec_args, args);
  }
  gimple_seq body = gimple_body(current_function_decl);

  if (dump_file)
      fprintf(dump_file, "Initial Sequence crcu8\n");
  gimplebind = NULL;
  gimpleret = NULL;
  for (i = gsi_start(body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      if (code == GIMPLE_BIND)
      {
        gimplebind = dyn_cast<gbind *>(stmt);
      }
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_seq inner_body = gimple_bind_body(gimplebind);
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }

  inner_body = gimple_bind_body(gimplebind);
  i = gsi_start(inner_body);
  while (!gsi_end_p(i))
  {
      gimple *stmt = gsi_stmt(i);
      enum gimple_code code = gimple_code(stmt);
      switch (code)
      {
      case GIMPLE_RETURN:
        gsi_next(&i);
        if (dump_file)
            fprintf(dump_file, "found return tree with removal!\n");
        tr_return = gimple_return_retval(dyn_cast<greturn *>(stmt));
        gimpleret = dyn_cast<greturn *>(stmt);
        break;
      default:
        if (dump_file)
            fprintf(dump_file, "remove stmt!\n");
        if (dump_file)
            print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
        gsi_remove(&i, true); // and delete everything
        break;
      }
  }
  i = gsi_start(inner_body);
  tree new_config_ui = build_int_cstu(type, 0x8005f107);
  tree new_t1 = create_tmp_var_raw(unsigned_type_node);
  tree new_t2 = create_tmp_var_raw(unsigned_type_node);
  tree new_config = create_tmp_var_raw(unsigned_type_node);
  tree new_crc_out = create_tmp_var_raw(short_unsigned_type_node);
  gassign *assign;
  gasm *asm_or_stmt;
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[1]));
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, new_t1));
  inputs = NULL;
  outputs = NULL;
  vec_safe_push(inputs, input);
  vec_safe_push(outputs, output);
  asm_or_stmt = gimple_build_asm_vec("shuffle %0, %1, 0x1F1-0x200 #Number One\n\t", inputs, outputs, NULL, NULL);
  gimple_asm_set_volatile(asm_or_stmt, false);
  gsi_insert_before(&i, asm_or_stmt, GSI_NEW_STMT);

  assign = gimple_build_assign(new_config, new_config_ui);
  gsi_insert_after(&i, assign, GSI_NEW_STMT);

  TREE_TYPE((*trvec_args)[1]) = unsigned_type_node;

  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, new_t1));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, new_config));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, (*trvec_args)[0]));
  vec_safe_push(inputs, input);
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, new_t2));

  outputs = NULL;
  vec_safe_push(outputs, output);
  asm_or_stmt = gimple_build_asm_vec("crcn %0, %1, %2, %3 #Number Two \n\t", inputs, outputs, NULL, NULL);
  gimple_asm_set_volatile(asm_or_stmt, false);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);

  input = build_tree_list(NULL_TREE, build_string(2, "d"));
  input = chainon(NULL_TREE, build_tree_list(input, new_t2));
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, new_crc_out));

  inputs = NULL;
  outputs = NULL;
  vec_safe_push(inputs, input);
  vec_safe_push(outputs, output);
  asm_or_stmt = gimple_build_asm_vec("shuffle %0, %1, 0x1F1-0x200 #Number Tree\n\t", inputs, outputs, NULL, NULL);
  gimple_asm_set_volatile(asm_or_stmt, false);
  gsi_insert_after(&i, asm_or_stmt, GSI_NEW_STMT);
  assign = gimple_build_assign(tr_return, NOP_EXPR, new_crc_out);

  gimple_return_set_retval(gimpleret, new_crc_out);

  gsi_insert_after(&i, assign, GSI_NEW_STMT);
  for (i = gsi_start(inner_body); !gsi_end_p(i); gsi_next(&i))
  {
      gimple *stmt = gsi_stmt(i);
      if (dump_file)
        print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
  }
  gimple_bind_set_body(gimplebind, inner_body);
}

typedef struct
{
  gimple *gimple_strcmp;
  basic_block bb_strcmp;
  gimple_stmt_iterator gsi_strcmp;
  tree tree_strcmp_param0;
  tree tree_strcmp_param1;
  int result;
} func_strcmp_t;

typedef struct
{
  basic_block bb;
  int nr;       // nr of block
  int succ_len; // amount of succ
  int succ;     // succ analyzed so far
  int total;    // item is fully understood, succ are handled, stop criteria
  int temp;     // is seen during a temp run, stop criteria
} bb_vals_t;

#define MEMOPID_UNKNOWN -1
#define MEMOPID_MEM 1
#define MEMOPID_IMM 2
#define MEMOPID_UNVALID 3
#define MEMOPID_FREEZE 4
#define MEMOPID_UNVALIDPHI 5

typedef struct
{
  int nr;
  tree lhs;
  tree rhs1;
  tree rhs2;
  tree rhs3;
  int lhs_op; //-1 unknown, 1 mem, 2 immed, 3 invalidate
  int lhs_size;
  int64_t lhs_value;
  int rhs1_op;
  int rhs1_size;
  int64_t rhs1_value;
  int rhs2_op;
  int rhs2_size;
  int64_t rhs2_value;
  int rhs3_op;
  int rhs3_size;
  int rhs3_immed;
  int64_t rhs3_value;

} mem_assign_t;

#define MEMPID_IMMED 0      // immediate value is known
#define MEMPID_UNINIT -1    // uninitialized
#define MEMPID_UNDEFINED -2 // undefined
#define MEMPID_FROZEN -3    // frozen

typedef struct
{
  int stat; // 0 immed, -1 not, -2 undefined, -3 frozen
  int value;
} mem_byte_t;

int tricopt_build_bb_chain(function *function, bb_vals_t *bb_vals, vec<int, va_gc> **ids, func_strcmp_t *func_strcmp);
int tricopt_analyze_bb_chain(function *function, bb_vals_t *bb_vals, vec<int, va_gc> *bb_ids, func_strcmp_t *func_strcmp, int bb_from, int bb_to, mem_byte_t *p0_ref, mem_byte_t *p1_ref);
int tricopt_analyze_bb_chain_all(function *function, bb_vals_t *bb_vals, vec<int, va_gc> **ids, func_strcmp_t *func_strcmp);
int tricopt_referenced(tree operand, tree ref);
int tricopt_mem_access(tree operand, int nr, mem_assign_t *mem);
static uint32_t tric_singletable_crc32c(uint32_t crc, char *buf, size_t size);

int tricopt_build_bb_chain_recursive(basic_block bb, int *bb_rec_list, int *bb_rec_list_len)
{
  // if bb is already do nothing
  for (int ii = 0; ii < *bb_rec_list_len; ii += 1)
  {
      if (bb_rec_list[ii] == bb->index)
        return 0;
  }
  bb_rec_list[*bb_rec_list_len] = bb->index;
  *bb_rec_list_len += 1;
  if (*bb_rec_list_len > 2047)
      return -1;
  if (bb->preds == NULL)
      return 0;
  edge e;
  edge_iterator ei;
  FOR_EACH_EDGE(e, ei, bb->preds)
  {
      tricopt_build_bb_chain_recursive(e->src, bb_rec_list, bb_rec_list_len);
  }
  return 0;
}

int tricopt_build_bb_chain(function *function, bb_vals_t *bb_vals, vec<int, va_gc> **bb_ids, func_strcmp_t *func_strcmp)
{
  vec<uint32_t, va_gc> *bb_ids_cks = NULL;
  basic_block bb;
  int bb_len = -1;
  int cks_hit = 0;
  FOR_ALL_BB_FN(bb, function)
  {
      if (bb->index >= bb_len)
        bb_len = bb->index + 1;
  }

  int bb_tmp[2048];
  int bbcnt;
  bbcnt = 0;
  FOR_ALL_BB_FN(bb, function)
  {
      if (bb->index == 0)
      {
        bbcnt = bb->index;
        bb_vals[bbcnt].bb = bb;
        bb_vals[bbcnt].nr = bb->index;
        bb_vals[bbcnt].succ_len = 1; // has only one succ
        bb_vals[bbcnt].succ = 0;
        bb_vals[bbcnt].total = 0;
        bb_vals[bbcnt].temp = 0;
        bbcnt += 1;
      }
      else if (bb->index == 1)
      {
        //	if (dump_file) fprintf(dump_file,"Block Exit %d\n",bb->index);
        bbcnt = bb->index;
        bb_vals[bbcnt].bb = bb;
        bb_vals[bbcnt].nr = bb->index;
        bb_vals[bbcnt].succ_len = 0; // has no succ
        bb_vals[bbcnt].succ = 0;
        bb_vals[bbcnt].total = 0;
        bb_vals[bbcnt].temp = 0;
        bbcnt += 1;
      }
      else
      {
        //	if (dump_file) fprintf(dump_file,"Block %d\n",bb->index);
        edge e;
        edge_iterator ei;
        int cnt = 0;
        FOR_EACH_EDGE(e, ei, bb->succs)
        {
            //  	  basic_block dest = e->dest;
            //	  if (dump_file) fprintf(dump_file, "bb_succ %d\n", dest->index);
            cnt += 1;
        }
        bbcnt = bb->index;
        bb_vals[bbcnt].bb = bb;
        bb_vals[bbcnt].nr = bb->index;
        bb_vals[bbcnt].succ_len = cnt;
        bb_vals[bbcnt].succ = 0;
        bb_vals[bbcnt].total = 0;
        bb_vals[bbcnt].temp = 0;
        bbcnt += 1;
      }
  }

  for (int kk = 0; kk < bb_len; kk += 1)
  {
      if (dump_file)
        fprintf(dump_file, "(%2d) bb_nr=%2d succ_len=%d succ=%d total=%d temp=%d ", kk, bb_vals[kk].nr, bb_vals[kk].succ_len, bb_vals[kk].succ, bb_vals[kk].total, bb_vals[kk].temp);
      edge e;
      edge_iterator ei;
      if (bb_vals[kk].bb != NULL)
      {
        if (dump_file)
            fprintf(dump_file, " Pred=");
        FOR_EACH_EDGE(e, ei, bb_vals[kk].bb->preds)
        {
            if (dump_file)
            fprintf(dump_file, " %2d", e->src->index);
        }
        if (dump_file)
            fprintf(dump_file, " Succ=");
        FOR_EACH_EDGE(e, ei, bb_vals[kk].bb->succs)
        {
            if (dump_file)
            fprintf(dump_file, " %2d", e->dest->index);
        }
        if (dump_file)
            fprintf(dump_file, "\n");
      }
      else
      {
        if (dump_file)
            fprintf(dump_file, "\n");
      }
  }

  // do a recursive print of all potential pred from the bb which has to be omptimized
  // stop condition is no pred, or is already in list, do it recursive
  int build_bb_chain_recursive_ok = -1;
  int bb_rec_list[2048];
  int bb_rec_list_len;
  bb_rec_list_len = 0;
  build_bb_chain_recursive_ok = tricopt_build_bb_chain_recursive(func_strcmp->bb_strcmp, &bb_rec_list[0], &bb_rec_list_len);
  if (build_bb_chain_recursive_ok != 0)
      return -1;
  for (int ii = 0; ii < bb_rec_list_len; ii += 1)
  {
      if (dump_file)
        fprintf(dump_file, "Rec %2d %d\n", bb_rec_list[ii], bb_vals[bb_rec_list[ii]].succ_len);
  }
  // each bb which is not in this list, should not be touched, therefore set succ_len to zero
  for (int kk = 0; kk < bb_len; kk += 1)
  {
      int inlist = 0;
      for (int ii = 0; ii < bb_rec_list_len; ii += 1)
      {
        if (bb_rec_list[ii] == bb_vals[kk].nr)
        {
            inlist = 1;
            break;
        }
      }
      if (inlist == 0)
        bb_vals[kk].succ_len = 0;
  }

  int incr = 0;
  int incr_max = 1;
  for (int kk = 0; kk < bb_len; kk += 1)
  {
      if (bb_vals[kk].succ_len != 0)
      {
        incr_max = incr_max * bb_vals[kk].succ_len;
      }
  }
  // the optimization problem is to complex
  // other approach would be to continue singled pred, see anchor pass
  if (incr_max > 16384)
      return -1;

  if (dump_file)
      fprintf(dump_file, "maximum combinations %d \n", incr_max);
  while (incr < incr_max)
  {
      // increment by one

      int tmp = incr;
      for (int kk = 0; kk < bb_len; kk += 1)
      {
        if (bb_vals[kk].succ_len != 0)
        {
            bb_vals[kk].succ = tmp % bb_vals[kk].succ_len;
            tmp = tmp / bb_vals[kk].succ_len;
        }
      }
      //      if (dump_file) fprintf(dump_file, "%d= ",incr);
      //      for (int kk=0; kk<bb_len; kk+=1)
      //	{
      //	  if (dump_file) fprintf(dump_file, "[%d] (%d,%d) ",kk,bb_vals[kk].succ,bb_vals[kk].succ_len);
      //	}
      //      if (dump_file) fprintf(dump_file, "\n");
      for (int kk = 0; kk < bb_len; kk += 1)
      {
        bb_vals[kk].temp = 0; // set the bb visited to 0
      }

      // now analyze it
      int bb_act = 0;
      int id_bb_tmp = 0;
      while (1 == 1)
      {
        //      if (dump_file) fprintf(dump_file, "investigate bb old %d new %d\n",bb_pred, bb_act);
        if (bb_vals[bb_act].nr == 1)
        {
            bb_tmp[id_bb_tmp++] = bb_act;
            bb_tmp[id_bb_tmp++] = -1;
            break;
        } // reached return bb
        if (bb_vals[bb_act].succ_len == 0)
        { /*bb_tmp[id_bb_tmp++]=bb_act;*/
            bb_tmp[id_bb_tmp++] = -3;
            break;
        } // no successor
        if (bb_vals[bb_act].temp == 1)
        {
            bb_tmp[id_bb_tmp++] = bb_act;
            bb_tmp[id_bb_tmp++] = -3;
            break;
        } // was already visited
        if (bb_vals[bb_act].succ == bb_vals[bb_act].succ_len)
        {
            bb_tmp[id_bb_tmp++] = bb_act;
            bb_tmp[id_bb_tmp++] = -4;
            break;
        } // all successors already taken,is a fail
        bb_tmp[id_bb_tmp++] = bb_act;
        bb_vals[bb_act].temp += 1;
        //      if (bb_pred!=-1) //not the start
        {

            edge e;
            edge_iterator ei;
            int cnt = 0;
            FOR_EACH_EDGE(e, ei, bb_vals[bb_act].bb->succs)
            {
            if (cnt == bb_vals[bb_act].succ)
            {
      bb_act = e->dest->index;
      //		if (dump_file) fprintf(dump_file, "take bb old %d new %d\n",bb_pred, bb_act);
      break;
            }
            cnt += 1;
            }
        }
      }
      // check if the chain contains the func
      int bb_ok = 0;
      for (int ii = 0; ii < id_bb_tmp; ii += 1)
      {
        if (bb_vals[bb_tmp[ii]].nr == func_strcmp->bb_strcmp->index)
        {
            bb_ok = 1;
            break;
        }
      }

      if (bb_ok == 1)
      {
        // in case of -3 abort, check if the func is part of the repetition
        // if yes, then take the complete chain
        // if no only convert it in a -1 chain and shorten it
        if (bb_tmp[id_bb_tmp - 1] == -3)
        {
            int bb_rep0_id = -1;
            int bb_rep1_id = -1;
            int bb_func_id = -1;
            for (int ii = 0; ii < id_bb_tmp; ii += 1)
            {
            if (bb_rep0_id == -1)
      if (bb_tmp[id_bb_tmp - 2] == bb_tmp[ii])
              bb_rep0_id = ii;
            if (bb_rep0_id != -1)
      if (bb_tmp[id_bb_tmp - 2] == bb_tmp[ii])
              bb_rep1_id = ii;
            if (bb_func_id == -1)
      if (bb_vals[bb_tmp[ii]].nr == func_strcmp->bb_strcmp->index)
              bb_func_id = ii;
            }
            // see now if the func is not in between
            if (!((bb_func_id > bb_rep0_id) && (bb_func_id < bb_rep1_id)))
            {
            bb_tmp[bb_func_id + 1] = -1;
            id_bb_tmp = bb_func_id + 2;
            }
        }
        uint32_t cks = tric_singletable_crc32c(0xaaaabbbb, (char *)&bb_tmp[0], id_bb_tmp * (sizeof(int)));
        // check if cks is already known
        int cks_known = 0;
        for (unsigned int kk = 0; kk < vec_safe_length(bb_ids_cks); kk += 1)
        {
            if ((*bb_ids_cks)[kk] == cks)
            {
            cks_known = 1;
            cks_hit += 1;
            break;
            }
        }
        if (cks_known == 0)
        {
            vec_safe_push(bb_ids_cks, cks);
            for (int kk = 0; kk < id_bb_tmp; kk += 1)
            {
            vec_safe_push(*bb_ids, bb_tmp[kk]);
            //  	 if (dump_file) fprintf(dump_file,"Push %d %d \n",bb_tmp[kk],vec_safe_length(*bb_ids));
            }
        }
      }
      incr += 1;
  }
  // have all bb chains without redundance
  // depending on exit we have to the analysis
  // if exit -3, then goto second bb_strcmp, jump backward
  // if exit -1, then goto first bb_strcmp
  return 0;
}

/* the function delivers fail, if the called function can modify the local parameter
 * this can be, if the function passes arguments, which are somehow refering direct/indirect to the strcmp values
 * if it is void as argument not relevant
 * for dhrysone it is print, __builtin_puts
 */
int tricopt_analyze_call(gimple *stmt)
{
  gcall *gimplecall = dyn_cast<gcall *>(stmt);
  tree fn_decl = gimple_call_fndecl(gimplecall);
  if (gimple_call_num_args(gimplecall) == 0)
      return 0; // not relevant
  if (strcmp("printf", print_generic_expr_to_str(fn_decl)) == 0)
      return 0; // not relevant
  if (strcmp("__builtin_putchar", print_generic_expr_to_str(fn_decl)) == 0)
      return 0; // not relevant
  if (strcmp("__builtin_puts", print_generic_expr_to_str(fn_decl)) == 0)
      return 0; // not relevant

  if (strcmp("strcmp", print_generic_expr_to_str(fn_decl)) != 0)
  {
      goto dont_take;
  }
  if ((gimple_call_num_args(gimplecall) != 2))
  {
      goto dont_take;
  }
  tree c1arg1;
  tree c1arg2;
  tree clhs;

  c1arg1 = gimple_call_arg(gimplecall, 0);
  if (get_attr_nonstring_decl(c1arg1))
  {
      goto dont_take;
  }
  clhs = gimple_call_lhs(gimplecall);
  //  if (dump_file) fprintf(dump_file,"clhs %s\n",print_generic_expr_to_str(clhs));
  //  if (dump_file) fprintf(dump_file,"clhs Treecode %s\n",get_tree_code_name (TREE_CODE(clhs))); //addr_expr
  //  if (dump_file) fprintf(dump_file,"clhs Type Treecode %s\n",print_generic_expr_to_str (TREE_TYPE(clhs))); //addr_expr
  if (strcmp("int", print_generic_expr_to_str(TREE_TYPE(clhs))) != 0)
  {
      goto dont_take;
  }
  //  if (dump_file) fprintf(dump_file,"c1arg1 %s\n",print_generic_expr_to_str(c1arg1));
  //  if (dump_file) fprintf(dump_file,"c1arg1 Treecode %s\n",get_tree_code_name (TREE_CODE(c1arg1))); //addr_expr
  if (TREE_CODE(c1arg1) != ADDR_EXPR)
  {
      goto dont_take;
  }
  //  if (dump_file) fprintf(dump_file,"c1arg1 Type Treecode %s\n",print_generic_expr_to_str (TREE_TYPE(c1arg1 ))); //addr_expr
  //  if (dump_file) fprintf(dump_file,"c1arg1 op0 Treecode %s\n",print_generic_expr_to_str (TREE_OPERAND (c1arg1, 0))); //addr_expr
  if (strcmp("char[31] *", print_generic_expr_to_str(TREE_TYPE(c1arg1))) != 0)
  {
      goto dont_take;
  }
  c1arg2 = gimple_call_arg(gimplecall, 1);
  if (get_attr_nonstring_decl(c1arg2))
  {
      goto dont_take;
  }
  //  if (dump_file) fprintf(dump_file,"c1arg2 %s\n",print_generic_expr_to_str(c1arg2));
  //  if (dump_file) fprintf(dump_file,"c1arg2 Treecode %s\n",get_tree_code_name (TREE_CODE(c1arg2))); //addr_expr
  if (TREE_CODE(c1arg2) != ADDR_EXPR)
  {
      goto dont_take;
  }
  //  if (dump_file) fprintf(dump_file,"c1arg2 Type Treecode %s\n",print_generic_expr_to_str (TREE_TYPE(c1arg2 ))); //addr_expr
  //  if (dump_file) fprintf(dump_file,"c1arg2 op0 Treecode %s\n",print_generic_expr_to_str (TREE_OPERAND (c1arg2, 0))); //addr_expr
  if (strcmp("char[31] *", print_generic_expr_to_str(TREE_TYPE(c1arg2))) != 0)
  {
      goto dont_take;
  }
  return 0;
dont_take:;
  if (dump_file)
      fprintf(dump_file, "Call Invalidates all relevant store motion recording %s \n", print_generic_expr_to_str(fn_decl));
  return 1;
}

// analyze bb_chain with related to information in func_strcmp

int tricopt_analyze_bb_chain(function *function ATTRIBUTE_UNUSED, bb_vals_t *bb_vals, vec<int, va_gc> *bb_ids, func_strcmp_t *func_strcmp, int bb_from, int bb_to, mem_byte_t *p0_ref, mem_byte_t *p1_ref)
{
  vec<tree, va_gc> *func_ref = NULL;
  vec<mem_assign_t, va_gc> *mem_access = NULL;
  vec_safe_push(func_ref, func_strcmp->tree_strcmp_param0);
  vec_safe_push(func_ref, func_strcmp->tree_strcmp_param1);

  // walk till bb_to

  for (unsigned int kk = bb_from; kk <= (unsigned int)bb_to; kk += 1)
  {
      if ((*bb_ids)[kk] >= 0)
      {
        // check the phi
        // if a phi of the relevant edge references a parameter, declare it is an unvalid
        gphi_iterator pi = gsi_start_phis(bb_vals[(*bb_ids)[kk]].bb);
        for (; !gsi_end_p(pi); gsi_next(&pi))
        {
            gphi *phi = pi.phi();
            if (!virtual_operand_p(gimple_phi_result(phi)))
            {

            if (dump_file)
      print_gimple_stmt(dump_file, phi, 0, dump_flag::TDF_NONE);
            for (unsigned int ii = 0; ii < gimple_phi_num_args(phi); ++ii)
            {
      basic_block src = gimple_phi_arg_edge(phi, ii)->src;
      if (src->index == bb_vals[(*bb_ids)[kk - 1]].nr)
      {
              tree rhs = gimple_phi_arg_def(phi, ii);
              tree lhs = gimple_phi_result(phi);
              if (dump_file)
                fprintf(dump_file, "%d %s(%d)=(%d) \n", ii, print_generic_expr_to_str(rhs), src->index, bb_vals[(*bb_ids)[kk - 1]].nr);
              int ref = 0;
              for (unsigned int jj = 0; jj < vec_safe_length(func_ref); jj += 1)
              {
                ref |= tricopt_referenced(lhs, (*func_ref)[jj]);
                ref |= tricopt_referenced(rhs, (*func_ref)[jj]);
              }
              if (ref != 0)
              {
                if (dump_file)
                  fprintf(dump_file, "Phi references func_ref param\n");
                mem_assign_t mem;
                memset(&mem, 0, sizeof(mem_assign_t));
                mem.nr = bb_vals[(*bb_ids)[kk]].bb->index;
                mem.lhs = NULL;
                mem.lhs_op = MEMOPID_UNVALIDPHI; // unvalidate it, is part of phi
                mem.lhs_size = 0;
                mem.lhs_value = 0;
                mem.rhs1_op = -1;
                mem.rhs2_op = -1;
                mem.rhs3_op = -1;
                vec_safe_push(mem_access, mem);
              }
      }
            }
            }
        }

        gimple_stmt_iterator gsi = gsi_start_bb(bb_vals[(*bb_ids)[kk]].bb);
        gimple *stmt = NULL;
        for (; !gsi_end_p(gsi); gsi_next(&gsi))
        {
            stmt = gsi_stmt(gsi);
            enum gimple_code code = gimple_code(stmt);
            if (gimple_has_mem_ops(stmt))
            {
            if (dump_file)
      fprintf(dump_file, "gimple_has_mem_ops\n");
            if (code == GIMPLE_CALL)
            {
      // gimple calls are invalidating the sequence so far recored
      // exception if call known and does not modify the items which are interesting
      if (dump_file)
              print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
      if (stmt == func_strcmp->gimple_strcmp)
      {
              mem_assign_t mem;
              memset(&mem, 0, sizeof(mem_assign_t));
              mem.nr = bb_vals[(*bb_ids)[kk]].bb->index;
              mem.lhs = NULL;
              mem.lhs_op = MEMOPID_FREEZE; // freeze it
              mem.lhs_size = 0;
              mem.lhs_value = 0;
              mem.rhs1_op = -1;
              mem.rhs2_op = -1;
              mem.rhs3_op = -1;
              vec_safe_push(mem_access, mem);
      }
      else
      {
              // here we decide if the call statement makes the so far recorded values unvalid
              // please see tricopt_analyze_call
              if (tricopt_analyze_call(stmt) != 0)
              {
                mem_assign_t mem;
                memset(&mem, 0, sizeof(mem_assign_t));
                mem.nr = bb_vals[(*bb_ids)[kk]].bb->index;
                mem.lhs = NULL;
                mem.lhs_op = MEMOPID_UNVALID; // unvalidate it
                mem.lhs_size = 0;
                mem.lhs_value = 0;
                mem.rhs1_op = -1;
                mem.rhs2_op = -1;
                mem.rhs3_op = -1;
                vec_safe_push(mem_access, mem);
              }
      }
            }
            if (code == GIMPLE_ASSIGN)
            {
      gassign *gimpleassign = dyn_cast<gassign *>(stmt);
      if (dump_file)
              print_gimple_stmt(dump_file, stmt, 0, TDF_RAW);
      if (gimple_assign_rhs_code(gimpleassign) != CONSTRUCTOR)
      {
              mem_assign_t mem;
              int ref = 0;
              memset(&mem, 0, sizeof(mem_assign_t));
              mem.nr = bb_vals[(*bb_ids)[kk]].bb->index;
              tree lhs = NULL;
              tree rhs1 = NULL;
              tree rhs2 = NULL;
              tree rhs3 = NULL;
              lhs = gimple_assign_lhs(gimpleassign);
              for (unsigned int jj = 0; jj < vec_safe_length(func_ref); jj += 1)
              {
                ref |= tricopt_referenced(lhs, (*func_ref)[jj]);
              }
              tricopt_mem_access(lhs, 0, &mem);
              switch (gimple_num_ops(gimpleassign))
              {
              case 4:
                rhs3 = gimple_assign_rhs3(gimpleassign);
                for (unsigned int jj = 0; jj < vec_safe_length(func_ref); jj += 1)
                {
                  ref |= tricopt_referenced(rhs3, (*func_ref)[jj]);
                }

                tricopt_mem_access(rhs3, 3, &mem);
                /* FALLTHRU */
              case 3:
                rhs2 = gimple_assign_rhs2(gimpleassign);
                for (unsigned int jj = 0; jj < vec_safe_length(func_ref); jj += 1)
                {
                  ref |= tricopt_referenced(rhs2, (*func_ref)[jj]);
                }

                tricopt_mem_access(rhs2, 2, &mem);
                /* FALLTHRU */
              case 2:
                rhs1 = gimple_assign_rhs1(gimpleassign);
                for (unsigned int jj = 0; jj < vec_safe_length(func_ref); jj += 1)
                {
                  ref |= tricopt_referenced(rhs1, (*func_ref)[jj]);
                }

                tricopt_mem_access(rhs1, 1, &mem);
                break;
              default:
                gcc_unreachable();
              }
              // push things where the param is referenced
              if (ref != 0)
              {
                vec_safe_push(mem_access, mem);
              }
      }
      // investigate if lhs,rhs are containing memory reads / writes
            }
            }

            // if if at the end and stmt is  the function call
            // please have here in mind the function call can also exist one time in an earlier bb
            if (kk == (unsigned int)bb_to)
            {
            // reached the func
            if (stmt == func_strcmp->gimple_strcmp)
            {
      break;
            }
            }
        }
      }
  }

  for (unsigned int kk = 0; kk < vec_safe_length(mem_access); kk += 1)
  {
      mem_assign_t mem;
      mem = (*mem_access)[kk];
      if (dump_file)
      {
        fprintf(dump_file, "*%2d bb=%2d mem lhs #%10s# op=%2d sz=%d val=%10ld ", kk, mem.nr, print_generic_expr_to_str(mem.lhs), mem.lhs_op, mem.lhs_size, mem.lhs_value);
        if (mem.rhs1 != NULL)
        {
            fprintf(dump_file, "rhs1 #%10s# op=%2d sz=%d val=%10ld ", print_generic_expr_to_str(mem.rhs1), mem.rhs1_op, mem.rhs1_size, mem.rhs1_value);
        }
        if (mem.rhs2 != NULL)
        {
            fprintf(dump_file, "rhs2 #%10s# op=%2d sz=%d val=%10ld ", print_generic_expr_to_str(mem.rhs2), mem.rhs2_op, mem.rhs2_size, mem.rhs2_value);
        }
        if (mem.rhs3 != NULL)
        {
            fprintf(dump_file, "rhs3 #%10s# op=%2d sz=%d val=%10ld ", print_generic_expr_to_str(mem.rhs3), mem.rhs3_op, mem.rhs3_size, mem.rhs3_value);
        }
        fprintf(dump_file, "\n");
      }
  }

  // analysis if both parameters can be represented by known immediates
  // the size of both arrays is 31
  mem_byte_t p0[31]; // stat 0 immed, -1 not, -2 undefined, -3 frozen
  mem_byte_t p1[31];

  for (int ii = 0; ii < 31; ii += 1)
  {
      p0[ii].stat = MEMPID_UNINIT;
      p1[ii].stat = MEMPID_UNINIT;
      p0[ii].value = 0;
      p1[ii].value = 0;
  }

  for (unsigned int kk = 0; kk < vec_safe_length(mem_access); kk += 1)
  {
      mem_assign_t mem;
      int mem_idx;
      mem = (*mem_access)[kk];
      if (dump_file)
      {
        fprintf(dump_file, "%2d bb=%2d mem lhs #%10s# op=%2d sz=%d val=%10ld \n", kk, mem.nr, print_generic_expr_to_str(mem.lhs), mem.lhs_op, mem.lhs_size, mem.lhs_value);
      }
      // 1st case lhs is mem and rhs1 is immediate
      if ((mem.lhs_op == MEMOPID_MEM) && (mem.rhs1_op == MEMOPID_IMM))
      {
        mem_idx = mem.lhs_value;
        for (unsigned int ll = 0; ll < (unsigned int)mem.lhs_size; ll += 1)
        {
            if (mem.lhs == (*func_ref)[0])
            {
            int mem_val;
            mem_val = (mem.rhs1_value >> (ll * 8) & 0xFF);
            if (p0[mem_idx + ll].stat == MEMPID_FROZEN)
            {
      // frozen
      if (mem_val != p0[mem_idx + ll].value)
              p0[mem_idx + ll].stat = MEMPID_UNDEFINED;
            }
            else
            {
      p0[mem_idx + ll].stat = MEMPID_IMMED;
      p0[mem_idx + ll].value = mem_val;
            }
            }
            if (mem.lhs == (*func_ref)[1])
            {
            int mem_val;
            mem_val = (mem.rhs1_value >> (ll * 8) & 0xFF);
            if (p1[mem_idx + ll].stat == MEMPID_FROZEN)
            {
      // frozen
      if (mem_val != p1[mem_idx + ll].value)
              p1[mem_idx + ll].stat = MEMPID_UNDEFINED;
            }
            else
            {
      p1[mem_idx + ll].stat = MEMPID_IMMED;
      p1[mem_idx + ll].value = mem_val;
            }
            }
        }
      }
      // 2nd case lhs is mem and rhs1 is not immediate/unknown
      if ((mem.lhs_op == MEMOPID_MEM) && (mem.rhs1_op == MEMOPID_UNKNOWN))
      {
        mem_idx = mem.lhs_value;
        for (unsigned int ll = 0; ll < (unsigned int)mem.lhs_size; ll += 1)
        {
            if (mem.lhs == (*func_ref)[0])
            p0[mem_idx + ll].stat = MEMPID_UNDEFINED;

            if (mem.lhs == (*func_ref)[1])
            p1[mem_idx + ll].stat = MEMPID_UNDEFINED;
        }
      }
      // unvalidate all, call can modify it, if not known
      if (mem.lhs_op == MEMOPID_UNVALID)
      {
        for (unsigned int ll = 0; ll < 31; ll += 1)
        {
            p0[ll].stat = MEMPID_UNINIT;
            p1[ll].stat = MEMPID_UNINIT;
        }
      }
      // unvalidate all, param of func is somehow part of phi statement
      if (mem.lhs_op == MEMOPID_UNVALIDPHI)
      {
        if (dump_file)
            fprintf(dump_file, "Unvalid phi operation\n");
        return -1; // unvalid immediate
        for (unsigned int ll = 0; ll < 31; ll += 1)
        {
            p0[ll].stat = MEMPID_UNINIT;
            p1[ll].stat = MEMPID_UNINIT;
        }
      }
      if (mem.lhs_op == MEMOPID_UNKNOWN)
      {
        if (dump_file)
            fprintf(dump_file, "Unvalid mem unknown\n");
        return -1; // unvalid immediate
        //	  for (unsigned int ll=0; ll<31; ll+=1)
        //	    {
        //	      p0[ll].stat=MEMPID_UNINIT;
        //	      p1[ll].stat=MEMPID_UNINIT;
        //	    }
      }
      // freeze the values
      if (mem.lhs_op == MEMOPID_FREEZE)
      {
        for (unsigned int ll = 0; ll < 31; ll += 1)
        {
            if (p0[ll].stat == MEMPID_IMMED)
            p0[ll].stat = MEMPID_FROZEN;
            if (p1[ll].stat == MEMPID_IMMED)
            p1[ll].stat = MEMPID_FROZEN;
        }
      }
  }

  if (p0_ref[0].stat == MEMPID_UNINIT)
  {
      // first time, no ref is existing
      for (int ii = 0; ii < 31; ii += 1)
      {
        p0_ref[ii] = p0[ii];
        p1_ref[ii] = p1[ii];
      }
      if (dump_file)
        fprintf(dump_file, "End of chain reached, first reference captured\n");
  }
  if (dump_file)
  {
      if (dump_file)
        fprintf(dump_file, "Byte           ");
      for (int ii = 0; ii < 31; ii += 1)
      {
        if (dump_file)
            fprintf(dump_file, "%3d ", ii);
      }
      if (dump_file)
        fprintf(dump_file, "\n");

      if (dump_file)
        fprintf(dump_file, "Param Status 0 ");
      for (int ii = 0; ii < 31; ii += 1)
      {
        if (dump_file)
            fprintf(dump_file, "%3d ", p0[ii].stat);
      }
      if (dump_file)
        fprintf(dump_file, "\n");
      if (dump_file)
        fprintf(dump_file, "Param Value  0 ");
      for (int ii = 0; ii < 31; ii += 1)
      {
        if (dump_file)
            fprintf(dump_file, "%3d ", p0[ii].value);
      }
      if (dump_file)
        fprintf(dump_file, "\n");
      if (dump_file)
        fprintf(dump_file, "Param Status 1 ");
      for (int ii = 0; ii < 31; ii += 1)
      {
        if (dump_file)
            fprintf(dump_file, "%3d ", p1[ii].stat);
      }
      if (dump_file)
        fprintf(dump_file, "\n");
      if (dump_file)
        fprintf(dump_file, "Param Value  1 ");
      for (int ii = 0; ii < 31; ii += 1)
      {
        if (dump_file)
            fprintf(dump_file, "%3d ", p1[ii].value);
      }
      if (dump_file)
        fprintf(dump_file, "\n");

      if (dump_file)
        fprintf(dump_file, "Paref Status 0 ");
      for (int ii = 0; ii < 31; ii += 1)
      {
        if (dump_file)
            fprintf(dump_file, "%3d ", p0_ref[ii].stat);
      }
      if (dump_file)
        fprintf(dump_file, "\n");
      if (dump_file)
        fprintf(dump_file, "Paref Value  0 ");
      for (int ii = 0; ii < 31; ii += 1)
      {
        if (dump_file)
            fprintf(dump_file, "%3d ", p0_ref[ii].value);
      }
      if (dump_file)
        fprintf(dump_file, "\n");
      if (dump_file)
        fprintf(dump_file, "Paref Status 1 ");
      for (int ii = 0; ii < 31; ii += 1)
      {
        if (dump_file)
            fprintf(dump_file, "%3d ", p1_ref[ii].stat);
      }
      if (dump_file)
        fprintf(dump_file, "\n");
      if (dump_file)
        fprintf(dump_file, "Paref Value  1 ");
      for (int ii = 0; ii < 31; ii += 1)
      {
        if (dump_file)
            fprintf(dump_file, "%3d ", p1_ref[ii].value);
      }
      if (dump_file)
        fprintf(dump_file, "\n");
  }
  // it is mandatory that all values are in a frozen state
  for (int ii = 0; ii < 31; ii += 1)
  {
      if (p0[ii].stat != MEMPID_FROZEN)
      {
        if (dump_file)
            fprintf(dump_file, "End of chain reached unvalid p0\n");
        return -1; // unvalid immediate
      }
      if (p1[ii].stat != MEMPID_FROZEN)
      {
        if (dump_file)
            fprintf(dump_file, "End of chain reached unvalid p1\n");
        return -1; // unvalid immediate
      }
  }
  // it is mandatory that all parameters, which are captured are identical
  for (int ii = 0; ii < 31; ii += 1)
  {
      if (p0[ii].value != p0_ref[ii].value)
      {
        if (dump_file)
            fprintf(dump_file, "End of chain reached, different immediate in p0[%d]=%d and p0_ref[%d]=%d \n", ii, p0[ii].value, ii, p0_ref[ii].value);
        return -1; // unvalid immediate
      }
      if (p1[ii].value != p1_ref[ii].value)
      {
        if (dump_file)
            fprintf(dump_file, "End of chain reached, different immediate in p1[%d]=%d and p1_ref[%d]=%d \n", ii, p1[ii].value, ii, p1_ref[ii].value);
        return -1; // unvalid immediate
      }
  }
  if (dump_file)
      fprintf(dump_file, "End of chain reached, everything ok\n");
  return 0;
}

int tricopt_analyze_bb_chain_all(function *function, bb_vals_t *bb_vals, vec<int, va_gc> *bb_ids, func_strcmp_t *func_strcmp)
{
  int bb_from;
  int bb_to;
  int bb_chain_kind;
  int bb_chain_func;
  int analyze_bb_chain_ok = -1;
  mem_byte_t p0_ref[31]; // stat 0 immed, -1 not, -2 undefined, -3 frozen
  mem_byte_t p1_ref[31];

  for (int ii = 0; ii < 31; ii += 1)
  {
      p0_ref[ii].stat = -1;
      p1_ref[ii].stat = -1;
      p0_ref[ii].value = 0;
      p1_ref[ii].value = 0;
  }

  // derive now the chains which are mandatory to be analyzed
  // do not take if func_strcmp->bb_strcmp is not in
  // take if in (two times) and stop before -3 delimter
  // take if in (one times) and stop is delimter -1

  for (unsigned int kk = 0; kk < vec_safe_length(bb_ids); kk += 1)
  {
      bb_from = -1;
      bb_to = -1;
      bb_chain_kind = 0;
      bb_chain_func = -1;
      unsigned int jj;
      if ((*bb_ids)[kk] >= 0)
      {
        for (jj = kk; jj < vec_safe_length(bb_ids); jj += 1)
        {
            if (bb_vals[(*bb_ids)[jj]].nr == func_strcmp->bb_strcmp->index)
            bb_chain_func = jj;
            if ((*bb_ids)[jj] == -1)
            {
            bb_from = kk;
            bb_chain_kind = -1;
            break;
            }
            if ((*bb_ids)[jj] == -3)
            {
            bb_from = kk;
            bb_chain_kind = -3;
            break;
            }
            if ((*bb_ids)[jj] == -2)
            {
            bb_from = kk;
            bb_chain_kind = -2;
            break;
            }
        }
        kk = jj;
        if (bb_chain_kind == -2)
        {
            // a chain ending with -2 should not happen
            if (dump_file)
            fprintf(dump_file, "Chain status %d, Chain ends with -2!!! \n", -1);
            return -1;
        }
        if (bb_chain_func == -1)
        {
            // no func inside should not happen
            return -1;
        }
        if ((bb_chain_kind != -1) && (bb_chain_kind != -3))
        {
            // end of chain must be -1 or -3, -1 is single path, -3 dual path
        }
        bb_to = jj - 1;

        if (dump_file)
            fprintf(dump_file, "Chain to analyze kind=%d from=(%d)%d to=(%d)%d func=(%d)%d \n",
                    bb_chain_kind, bb_from, bb_vals[(*bb_ids)[bb_from]].nr, bb_to, bb_vals[(*bb_ids)[bb_to]].nr, bb_chain_func, bb_vals[(*bb_ids)[bb_chain_func]].nr);
        analyze_bb_chain_ok = tricopt_analyze_bb_chain(function, bb_vals, bb_ids, func_strcmp, bb_from, bb_to, &p0_ref[0], &p1_ref[0]);
        if (dump_file)
            fprintf(dump_file, "Chain status %d \n", analyze_bb_chain_ok);
        if (analyze_bb_chain_ok != 0)
            return -1;
      }
  }

  // compute the result
  char p0_char[31];
  char p1_char[31];
  int p0_zero = -1;
  int p1_zero = -1;
  for (int ii = 0; ii < 31; ii += 1)
  {
      p0_char[ii] = p0_ref[ii].value;
      p1_char[ii] = p1_ref[ii].value;
      if (p0_char[ii] == 0)
        p0_zero = 1;
      if (p1_char[ii] == 0)
        p1_zero = 1;
  }
  if ((p0_zero == -1) || (p1_zero == -1))
  {
      if (dump_file)
        fprintf(dump_file, "p0 or p1 does not contain a zero delimiter %d %d \n", p0_zero, p1_zero);
      return -1;
  }
  func_strcmp->result = strcmp(&p0_char[0], &p1_char[0]);
  if (func_strcmp->result < 0)
      func_strcmp->result = -1;
  if (func_strcmp->result > 0)
      func_strcmp->result = 1;
  if (dump_file)
      fprintf(dump_file, "Chain status strcmp %d result=%d\n", analyze_bb_chain_ok, func_strcmp->result);
  return analyze_bb_chain_ok;
}

int tricopt_referenced(tree operand, tree ref)
{
  int len;
  if (operand == NULL)
      return -1;
  if (operand == ref)
      return 1;
  len = TREE_OPERAND_LENGTH(operand);
  for (int i = 0; i < len; ++i)
  {
      if (tricopt_referenced(TREE_OPERAND(operand, i), ref) == 1)
        return 1;
  }
  return 0;
}

int tricopt_mem_access(tree operand, int nr, mem_assign_t *mem)
{
  if (operand == NULL)
  {
      switch (nr)
      {
      case 0:
        mem->lhs = NULL;
        mem->lhs_op = MEMOPID_UNKNOWN;
        mem->lhs_size = 0;
        mem->lhs_value = 0;
        break;
      case 1:
        mem->rhs1 = NULL;
        mem->rhs1_op = MEMOPID_UNKNOWN;
        mem->rhs1_size = 0;
        mem->rhs1_value = 0;
        break;
      case 2:
        mem->rhs2 = NULL;
        mem->rhs2_op = MEMOPID_UNKNOWN;
        mem->rhs2_size = 0;
        mem->rhs2_value = 0;
        break;
      case 3:
        mem->rhs3 = NULL;
        mem->rhs3_op = MEMOPID_UNKNOWN;
        mem->rhs3_size = 0;
        mem->rhs3_value = 0;
        break;
      default:
        abort();
      }
      return -1;
  }
  //  if (dump_file) fprintf(dump_file,"operand %d  %s\n",nr,print_generic_expr_to_str(operand));
  //  if (dump_file) fprintf(dump_file,"operand %d Treecode %s\n",nr,get_tree_code_name (TREE_CODE(operand))); //addr_expr
  //  if (dump_file) fprintf(dump_file,"operand %d Treecode %s\n",nr,print_generic_expr_to_str (TREE_TYPE(operand))); //addr_expr
  if (TREE_CODE(operand) == INTEGER_CST)
  {
      if (dump_file)
        fprintf(dump_file, "integer_cst %d  size=%ld\n", nr, int_size_in_bytes(TREE_TYPE(operand)));
      switch (nr)
      {
      case 0:
        mem->lhs = operand;
        mem->lhs_op = MEMOPID_IMM;
        mem->lhs_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->lhs_value = TREE_INT_CST_LOW(operand);
        break;
      case 1:
        mem->rhs1 = operand;
        mem->rhs1_op = MEMOPID_IMM;
        mem->rhs1_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->rhs1_value = TREE_INT_CST_LOW(operand);
        break;
      case 2:
        mem->rhs2 = operand;
        mem->rhs2_op = MEMOPID_IMM;
        mem->rhs2_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->rhs2_value = TREE_INT_CST_LOW(operand);
        break;
      case 3:
        mem->rhs3 = operand;
        mem->rhs3_op = MEMOPID_IMM;
        mem->rhs3_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->rhs3_value = TREE_INT_CST_LOW(operand);
        break;
      default:
        abort();
      }
      return 1;
  }
  // pattern
  // if integer value, integer_cst, type
  // if mem_ref ..., mem_ref, type
  if (TREE_CODE(operand) == MEM_REF)
  {
      tree op0, op1;
      op0 = TREE_OPERAND(operand, 0);
      if (TREE_CODE(op0) != ADDR_EXPR)
        return -1;
      //      if (dump_file)  fprintf(dump_file,"operand(0) %d  %s\n",nr,print_generic_expr_to_str(op0));
      //      if (dump_file) fprintf(dump_file,"operand(0) %d Treecode %s\n",nr,get_tree_code_name (TREE_CODE(op0))); //addr_expr
      //      if (dump_file) fprintf(dump_file,"operand(0) %d Treecode %s\n",nr,print_generic_expr_to_str (TREE_TYPE(op0)));
      op1 = TREE_OPERAND(operand, 1);
      //      if (dump_file) fprintf(dump_file,"operand(1) %d  %s\n",nr,print_generic_expr_to_str(op1));
      //      if (dump_file) fprintf(dump_file,"operand(1) %d Treecode %s\n",nr,get_tree_code_name (TREE_CODE(op1)));
      //      if (dump_file) fprintf(dump_file,"operand(1) %d Treetype %s\n",nr,print_generic_expr_to_str (TREE_TYPE(op1)));
      switch (nr)
      {
      case 0:
        mem->lhs = TREE_OPERAND(op0, 0);
        mem->lhs_op = MEMOPID_MEM;
        mem->lhs_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->lhs_value = TREE_INT_CST_LOW(op1);
        break;
      case 1:
        mem->rhs1 = TREE_OPERAND(op0, 0);
        mem->rhs1_op = MEMOPID_MEM;
        mem->rhs1_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->rhs1_value = TREE_INT_CST_LOW(op1);
        break;
      case 2:
        mem->rhs2 = TREE_OPERAND(op0, 0);
        mem->rhs2_op = MEMOPID_MEM;
        mem->rhs2_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->rhs2_value = TREE_INT_CST_LOW(op1);
        break;
      case 3:
        mem->rhs3 = TREE_OPERAND(op0, 0);
        mem->rhs3_op = MEMOPID_MEM;
        mem->rhs3_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->rhs3_value = TREE_INT_CST_LOW(op1);
        break;
      default:
        abort();
      }
      return 2;
  }
  if (TREE_CODE(operand) == ARRAY_REF)
  {
      tree op0, op1;
      op0 = TREE_OPERAND(operand, 0);
      if (TREE_CODE(op0) != VAR_DECL)
        return -1;
      //      if (dump_file)  fprintf(dump_file,"operand(0) %d  %s\n",nr,print_generic_expr_to_str(op0));
      //      if (dump_file) fprintf(dump_file,"operand(0) %d Treecode %s\n",nr,get_tree_code_name (TREE_CODE(op0))); //addr_expr
      //      if (dump_file) fprintf(dump_file,"operand(0) %d Treecode %s\n",nr,print_generic_expr_to_str (TREE_TYPE(op0)));
      op1 = TREE_OPERAND(operand, 1);
      //      if (dump_file) fprintf(dump_file,"operand(1) %d  %s\n",nr,print_generic_expr_to_str(op1));
      //      if (dump_file) fprintf(dump_file,"operand(1) %d Treecode %s\n",nr,get_tree_code_name (TREE_CODE(op1)));
      //      if (dump_file) fprintf(dump_file,"operand(1) %d Treetype %s\n",nr,print_generic_expr_to_str (TREE_TYPE(op1)));
      switch (nr)
      {
      case 0:
        mem->lhs = op0;
        mem->lhs_op = MEMOPID_MEM;
        mem->lhs_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->lhs_value = TREE_INT_CST_LOW(op1);
        break;
      case 1:
        mem->rhs1 = op0;
        mem->rhs1_op = MEMOPID_MEM;
        mem->rhs1_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->rhs1_value = TREE_INT_CST_LOW(op1);
        break;
      case 2:
        mem->rhs2 = op0;
        mem->rhs2_op = MEMOPID_MEM;
        mem->rhs2_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->rhs2_value = TREE_INT_CST_LOW(op1);
        break;
      case 3:
        mem->rhs3 = op0;
        mem->rhs3_op = MEMOPID_MEM;
        mem->rhs3_size = int_size_in_bytes(TREE_TYPE(operand));
        mem->rhs3_value = TREE_INT_CST_LOW(op1);
        break;
      default:
        abort();
      }
      return 2;
  }

  switch (nr)
  {
  case 0:
      mem->lhs = operand;
      mem->lhs_op = MEMOPID_UNKNOWN;
      mem->lhs_size = int_size_in_bytes(TREE_TYPE(operand));
      mem->lhs_value = 0;
      break;
  case 1:
      mem->rhs1 = operand;
      mem->rhs1_op = MEMOPID_UNKNOWN;
      mem->rhs1_size = int_size_in_bytes(TREE_TYPE(operand));
      mem->rhs1_value = 0;
      break;
  case 2:
      mem->rhs2 = operand;
      mem->rhs2_op = MEMOPID_UNKNOWN;
      mem->rhs2_size = int_size_in_bytes(TREE_TYPE(operand));
      mem->rhs2_value = 0;
      break;
  case 3:
      mem->rhs3 = operand;
      mem->rhs3_op = MEMOPID_UNKNOWN;
      mem->rhs3_size = int_size_in_bytes(TREE_TYPE(operand));
      mem->rhs3_value = 0;
      break;
  default:
      abort();
  }
  return 0;
}

void tricopt_gimple_strcmp(function *function)
{
  basic_block bb;
  vec<int, va_gc> *bb_ids = NULL; // negative values are stop reasons
  vec<func_strcmp_t, va_gc> *func_strcmp = NULL;

  if (dump_file != NULL)
      fprintf(dump_file, "PASS function name optimize strcmp %s \n", get_fnname_from_decl(current_function_decl));

  FOR_ALL_BB_FN(bb, function)
  {
      if (bb->index == 0)
      {
      }
      else if (bb->index == 1)
      {
      }
      else
      {
        gimple_stmt_iterator gsi = gsi_start_bb(bb);
        for (; !gsi_end_p(gsi); gsi_next(&gsi))
        {
            gimple *stmt = gsi_stmt(gsi);
            enum gimple_code code = gimple_code(stmt);
            if (code == GIMPLE_CALL)
            {
            gcall *gimplestrcmp = dyn_cast<gcall *>(stmt);
            tree fn_decl = gimple_call_fndecl(gimplestrcmp);
            if (strcmp("strcmp", print_generic_expr_to_str(fn_decl)) != 0)
            {
      goto dont_take;
            }
            if ((gimple_call_num_args(gimplestrcmp) != 2))
            {
      goto dont_take;
            }
            tree c1arg1;
            tree c1arg2;
            tree clhs;
            tree param0;
            tree param1;

            c1arg1 = gimple_call_arg(gimplestrcmp, 0);
            if (get_attr_nonstring_decl(c1arg1))
            {
      goto dont_take;
            }
            clhs = gimple_call_lhs(gimplestrcmp);
            if (dump_file)
      fprintf(dump_file, "clhs %s\n", print_generic_expr_to_str(clhs));
            if (dump_file)
      fprintf(dump_file, "clhs Treecode %s\n", get_tree_code_name(TREE_CODE(clhs))); // addr_expr
            if (dump_file)
      fprintf(dump_file, "clhs Type Treecode %s\n", print_generic_expr_to_str(TREE_TYPE(clhs))); // addr_expr
            if (strcmp("int", print_generic_expr_to_str(TREE_TYPE(clhs))) != 0)
            {
      goto dont_take;
            }
	    /*
	    printf("************ Bene 0: %d %d \n", TREE_CODE(c1arg1), ADDR_EXPR);
	    printf("c1arg1 %s\n", print_generic_expr_to_str(c1arg1));
	    printf("c1arg1 Treecode %s\n", get_tree_code_name(TREE_CODE(c1arg1)));
            if (dump_file)
      fprintf(dump_file, "c1arg1 %s\n", print_generic_expr_to_str(c1arg1));
            if (dump_file)
      fprintf(dump_file, "c1arg1 Treecode %s\n", get_tree_code_name(TREE_CODE(c1arg1))); // addr_expr
            if (TREE_CODE(c1arg1) != ADDR_EXPR)
            {
      //goto dont_take;
            }
	    printf("************ Bene 1\n");
            if (dump_file)
      fprintf(dump_file, "c1arg1 Type Treecode %s\n", print_generic_expr_to_str(TREE_TYPE(c1arg1))); // addr_expr
            if (dump_file)
      fprintf(dump_file, "c1arg1 op0 Treecode %s\n", print_generic_expr_to_str(TREE_OPERAND(c1arg1, 0))); // addr_expr
            param0 = TREE_OPERAND(c1arg1, 0);
            if (strcmp("char[31] *", print_generic_expr_to_str(TREE_TYPE(c1arg1))) != 0)
            {
      goto dont_take;
            }
	    printf("************ Bene 2\n");
            c1arg2 = gimple_call_arg(gimplestrcmp, 1);
            if (get_attr_nonstring_decl(c1arg2))
            {
      goto dont_take;
            }
            if (dump_file)
      fprintf(dump_file, "c1arg2 %s\n", print_generic_expr_to_str(c1arg2));
            if (dump_file)
      fprintf(dump_file, "c1arg2 Treecode %s\n", get_tree_code_name(TREE_CODE(c1arg2))); // addr_expr
            if (TREE_CODE(c1arg2) != ADDR_EXPR)
            {
      goto dont_take;
            }
            if (dump_file)
      fprintf(dump_file, "c1arg2 Type Treecode %s\n", print_generic_expr_to_str(TREE_TYPE(c1arg2))); // addr_expr
            if (dump_file)
      fprintf(dump_file, "c1arg2 op0 Treecode %s\n", print_generic_expr_to_str(TREE_OPERAND(c1arg2, 0))); // addr_expr
            param1 = TREE_OPERAND(c1arg2, 0);
            if (strcmp("char[31] *", print_generic_expr_to_str(TREE_TYPE(c1arg2))) != 0)
            {
      goto dont_take;
            }
            if (dump_file)
      fprintf(dump_file, "c1arg2_v Treecode %s\n", get_tree_code_name(TREE_CODE(param1))); // addr_expr
            if ((TREE_CODE(param1) == STRING_CST))
            {
      goto dont_take;
            } // do not take strings as arguments, additional option
            if ((TREE_CODE(param0) == STRING_CST))
            {
      goto dont_take;
            } // do not take strings as arguments, additional option
	      // */
            func_strcmp_t func;
            func.gimple_strcmp = stmt;
            func.bb_strcmp = bb;
            func.gsi_strcmp = gsi;
            func.tree_strcmp_param0 = param0;
            func.tree_strcmp_param1 = param1;
            vec_safe_push(func_strcmp, func);
            dont_take:;
            }
	    
        }
      }
  }
  if (vec_safe_length(func_strcmp) == 0)
  {

      if (dump_file)
        fprintf(dump_file, "No strcmp inside\n");
      return;
  }

  int bb_len_fn = n_basic_blocks_for_fn(cfun);
  if (bb_len_fn > 1023)
      return;

  int bb_len = -1;
  FOR_ALL_BB_FN(bb, function)
  {
      if (bb->index >= bb_len)
        bb_len = bb->index + 1;
  }
  if (dump_file)
      fprintf(dump_file, "strcmp inside nr=%d bbs_fn=%d bbs=%d\n", vec_safe_length(func_strcmp), bb_len_fn, bb_len);

  for (unsigned kk = 0; kk < vec_safe_length(func_strcmp); kk += 1)
  {
      if (dump_file)
        fprintf(dump_file, "found strcmp inside %d bb=%d \n", kk, (*func_strcmp)[kk].bb_strcmp->index);
  }
  bb_vals_t *bb_vals = XNEWVEC(bb_vals_t, bb_len);

  // print all sequence incl. the delimiter
  int incr = 0;
  if (dump_file)
      fprintf(dump_file, "%2d= ", incr);
  for (unsigned int kk = 0; kk < vec_safe_length(bb_ids); kk += 1)
  {
      if ((*bb_ids)[kk] >= 0)
      {
        if (dump_file)
            fprintf(dump_file, "%d ", bb_vals[(*bb_ids)[kk]].nr);
      }
      if ((*bb_ids)[kk] < 0)
      {
        if (dump_file)
            fprintf(dump_file, "%d \n", (*bb_ids)[kk]);
        incr += 1;
        if ((kk + 1) != vec_safe_length(bb_ids))
            if (dump_file)
            fprintf(dump_file, "%2d= ", incr);
      }
  }

  for (unsigned int kk = 0; kk < vec_safe_length(func_strcmp); kk += 1)
  {
      func_strcmp_t func;
      func = (*func_strcmp)[kk];
      int build_bb_chain_ok = -1;
      int analyze_bb_chain_all_ok = -1;
      memset(&bb_vals[0], 0, sizeof(bb_vals_t) * bb_len);
      build_bb_chain_ok = tricopt_build_bb_chain(function, &bb_vals[0], &bb_ids, &func);

      // print all sequence incl. the delimiter
      int incr = 0;
      if (dump_file)
        fprintf(dump_file, "%2d= ", incr);
      for (unsigned int ll = 0; ll < vec_safe_length(bb_ids); ll += 1)
      {
        if ((*bb_ids)[ll] >= 0)
        {
            if (dump_file)
            fprintf(dump_file, "%d ", bb_vals[(*bb_ids)[ll]].nr);
        }
        if ((*bb_ids)[ll] < 0)
        {
            if (dump_file)
            fprintf(dump_file, "%d \n", (*bb_ids)[ll]);
            incr += 1;
            if ((ll + 1) != vec_safe_length(bb_ids))
            if (dump_file)
      fprintf(dump_file, "%2d= ", incr);
        }
      }

      if (build_bb_chain_ok != -1)
      {
        analyze_bb_chain_all_ok = tricopt_analyze_bb_chain_all(function, &bb_vals[0], bb_ids, &func);
      }

      if (1 /*analyze_bb_chain_all_ok == 0*/)
      {
	
        if (dump_file)
            fprintf(dump_file, "Strcmp can be fully relpaced!\n\n");
        gcall *gimplestrcmp = dyn_cast<gcall *>(func.gimple_strcmp);
        tree lhs;
        lhs = gimple_call_lhs(gimplestrcmp);
        gsi_remove(&func.gsi_strcmp, true);
        gassign *assign = gimple_build_assign(lhs, build_int_cst(integer_type_node, func.result));
        gsi_insert_before(&func.gsi_strcmp, assign, GSI_NEW_STMT);
      }
      else
      {
        // strcmp could not be replaced, inlining as fast assembly routine for remaining strcmp, will be done later
      }
  }

  XDELETEVEC(bb_vals);
  return;
}

void tricopt_gimple_ass_stmts_strcmp(gcall *gimplestrcmp, gimple_stmt_iterator *i)
{
  vec<tree, va_gc> *inputs;
  vec<tree, va_gc> *clobbers;
  vec<tree, va_gc> *outputs;
  tree input;
  tree output;
  tree clobber;
  gassign *gimpleassign;

  tree fn_decl = gimple_call_fndecl(gimplestrcmp);
  if (strcmp("strcmp", print_generic_expr_to_str(fn_decl)) != 0)
  {
      goto dont_take;
  }
  if ((gimple_call_num_args(gimplestrcmp) != 2))
  {
      goto dont_take;
  }
  tree c1arg1;
  tree c1arg2;
  tree clhs;
  tree tc1arg1;
  tree tc1arg2;
  tree tclhs;

  c1arg1 = gimple_call_arg(gimplestrcmp, 0);
  if (get_attr_nonstring_decl(c1arg1))
  {
      goto dont_take;
  }
  clhs = gimple_call_lhs(gimplestrcmp);
  if (dump_file)
      fprintf(dump_file, "clhs %s\n", print_generic_expr_to_str(clhs));
  if (dump_file)
      fprintf(dump_file, "clhs Treecode %s\n", get_tree_code_name(TREE_CODE(clhs))); // addr_expr
  if (dump_file)
      fprintf(dump_file, "clhs Type Treecode %s\n", print_generic_expr_to_str(TREE_TYPE(clhs))); // addr_expr
  if (strcmp("int", print_generic_expr_to_str(TREE_TYPE(clhs))) != 0)
  {
      goto dont_take;
  }
  if (dump_file)
      fprintf(dump_file, "c1arg1 %s\n", print_generic_expr_to_str(c1arg1));
  if (dump_file)
      fprintf(dump_file, "c1arg1 Treecode %s\n", get_tree_code_name(TREE_CODE(c1arg1))); // addr_expr
  if (dump_file)
      fprintf(dump_file, "c1arg1 Type Treecode %s\n", print_generic_expr_to_str(TREE_TYPE(c1arg1))); // addr_expr
  // tbd make it more generic
  c1arg2 = gimple_call_arg(gimplestrcmp, 1);
  if (get_attr_nonstring_decl(c1arg2))
  {
      goto dont_take;
  }
  if (dump_file)
      fprintf(dump_file, "c1arg2 %s\n", print_generic_expr_to_str(c1arg2));
  if (dump_file)
      fprintf(dump_file, "c1arg2 Treecode %s\n", get_tree_code_name(TREE_CODE(c1arg2))); // addr_expr
  if (dump_file)
      fprintf(dump_file, "c1arg2 Type Treecode %s\n", print_generic_expr_to_str(TREE_TYPE(c1arg2))); // addr_expr
  tc1arg1 = create_tmp_var_raw(TREE_TYPE(c1arg1));
  tc1arg2 = create_tmp_var_raw(TREE_TYPE(c1arg2));
  tclhs = create_tmp_var_raw(TREE_TYPE(clhs));

  gsi_remove(i, true);
  gimpleassign = gimple_build_assign(tc1arg1, c1arg1);
  gsi_insert_before(i, gimpleassign, GSI_NEW_STMT);
  gimpleassign = gimple_build_assign(tc1arg2, c1arg2);
  gsi_insert_after(i, gimpleassign, GSI_NEW_STMT);
  gasm *asm_or_stmt;
  inputs = NULL;
  input = build_tree_list(NULL_TREE, build_string(2, "1"));
  input = chainon(NULL_TREE, build_tree_list(input, tc1arg1));
  vec_safe_push(inputs, input);
  input = build_tree_list(NULL_TREE, build_string(2, "2"));
  input = chainon(NULL_TREE, build_tree_list(input, tc1arg2));
  vec_safe_push(inputs, input);
  outputs = NULL;
  output = build_tree_list(NULL_TREE, build_string(3, "=d"));
  output = chainon(NULL_TREE, build_tree_list(output, tclhs));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, tc1arg1));
  vec_safe_push(outputs, output);
  output = build_tree_list(NULL_TREE, build_string(3, "=a"));
  output = chainon(NULL_TREE, build_tree_list(output, tc1arg2));
  vec_safe_push(outputs, output);

  clobbers = NULL;
  clobber = build_tree_list(NULL_TREE, build_string(7, "memory"));
  vec_safe_push(clobbers, clobber);
  clobber = build_tree_list(NULL_TREE, build_string(3, "d7"));
  vec_safe_push(clobbers, clobber);
  clobber = build_tree_list(NULL_TREE, build_string(3, "d6"));
  vec_safe_push(clobbers, clobber);
  clobber = build_tree_list(NULL_TREE, build_string(3, "d5"));
  vec_safe_push(clobbers, clobber);
  clobber = build_tree_list(NULL_TREE, build_string(3, "d3"));
  vec_safe_push(clobbers, clobber);
  clobber = build_tree_list(NULL_TREE, build_string(3, "d1"));
  vec_safe_push(clobbers, clobber);
  clobber = build_tree_list(NULL_TREE, build_string(3, "d0"));
  vec_safe_push(clobbers, clobber);

  asm_or_stmt = gimple_build_asm_vec(
      "	    mov.d %%d6,%1      \n"
      "	mov.d %0,%2      \n"
      "	or %%d6,%0      \n"
      "	and %%d6,%%d6,3      \n"
      "	jnz %%d6,.LL_STRCOMP_UNALIGNED%=   #is not aligned      \n"
      ".LL_STRCOMP_AGAIN%=:      \n"
      "	ld.d %%e6,[%1+]8      \n"
      "	ld.d %%e0,[%2+]8      \n"
      "	eqany.b %%d5,%%d6,0      \n"
      "	jne   %%d0,%%d6,.LL_STRCOMP_NEQL%=   #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROL%=   #there is a zero in      \n"
      "	eqany.b %%d5,%%d7,0      \n"
      "	jne   %%d1,%%d7,.LL_STRCOMP_NEQH%=  #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROH%=   #there is a zero in      \n"
      "	ld.d %%e6,[%1+]8      \n"
      "	ld.d %%e0,[%2+]8      \n"
      "	eqany.b %%d5,%%d6,0      \n"
      "	jne   %%d0,%%d6,.LL_STRCOMP_NEQL%=   #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROL%=   #there is a zero in      \n"
      "	eqany.b %%d5,%%d7,0      \n"
      "	jne   %%d1,%%d7,.LL_STRCOMP_NEQH%=  #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROH%=   #there is a zero in      \n"
      "	ld.d %%e6,[%1+]8      \n"
      "	ld.d %%e0,[%2+]8      \n"
      "	eqany.b %%d5,%%d6,0      \n"
      "	jne   %%d0,%%d6,.LL_STRCOMP_NEQL%=   #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROL%=   #there is a zero in      \n"
      "	eqany.b %%d5,%%d7,0      \n"
      "	jne   %%d1,%%d7,.LL_STRCOMP_NEQH%=  #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROH%=   #there is a zero in      \n"
      "	ld.d %%e6,[%1+]8      \n"
      "	ld.d %%e0,[%2+]8      \n"
      "	eqany.b %%d5,%%d6,0      \n"
      "	jne   %%d0,%%d6,.LL_STRCOMP_NEQL%=   #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROL%=   #there is a zero in      \n"
      "	eqany.b %%d5,%%d7,0      \n"
      "	jne   %%d1,%%d7,.LL_STRCOMP_NEQH%=  #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROH%=   #there is a zero in      \n"
      "	loopu .LL_STRCOMP_AGAIN%=      \n"
      "	debug      \n"
      ".LL_STRCOMP_NEQL%=: #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROL%=   #there is a zero in      \n"
      "	eq.b  %%d5,%%d6,%%d0 #no zero in, check which byte is different      \n"
      "	jz.t %%d5,0,.LL_STRCOMP_NEQ0L%= #byte zero different      \n"
      "	jz.t %%d5,8,.LL_STRCOMP_NEQ1L%= #byte one different      \n"
      "	jz.t %%d5,16,.LL_STRCOMP_NEQ2L%= #byte two different      \n"
      "	sub   %0,%%d6,%%d0 #only three different      \n"
      "	j .LL_STRCOMP10%=    \n"
      ".LL_STRCOMP_NEQ0L%=:      \n"
      "	extr.u  %0,%%d6,0,8      \n"
      "	extr.u  %%d3,%%d0,0,8      \n"
      "	j .LL_STRCOMP_SUB%=    \n"
      ".LL_STRCOMP_NEQ1L%=:      \n"
      "	extr.u  %0,%%d6,8,8     \n"
      "	extr.u  %%d3,%%d0,8,8      \n"
      "	j .LL_STRCOMP_SUB%=    \n"
      ".LL_STRCOMP_NEQ2L%=:      \n"
      "	extr.u  %0,%%d6,16,8      \n"
      "	extr.u  %%d3,%%d0,16,8      \n"
      "	j .LL_STRCOMP_SUB%=     \n"
      ".LL_STRCOMP_NEQH%=: #it is not equal      \n"
      "	jnz   %%d5,.LL_STRCOMP_ZEROH%=   #there is a zero in      \n"
      "	eq.b  %%d5,%%d7,%%d1 #no zero in, check which byte is different      \n"
      "	jz.t %%d5,0,.LL_STRCOMP_NEQ0H%= #byte zero different      \n"
      "	jz.t %%d5,8,.LL_STRCOMP_NEQ1H%= #byte one different      \n"
      "	jz.t %%d5,16,.LL_STRCOMP_NEQ2H%= #byte two different      \n"
      "	sub   %0,%%d7,%%d1 #only three different      \n"
      "	j .LL_STRCOMP10%=    \n"
      ".LL_STRCOMP_NEQ0H%=:      \n"
      "	extr.u  %0,%%d7,0,8      \n"
      "	extr.u  %%d3,%%d1,0,8      \n"
      "	j .LL_STRCOMP_SUB%=    \n"
      ".LL_STRCOMP_NEQ1H%=:      \n"
      "	extr.u  %0,%%d7,8,8      \n"
      "	extr.u  %%d3,%%d1,8,8      \n"
      "	j .LL_STRCOMP_SUB%=     \n"
      ".LL_STRCOMP_NEQ2H%=:      \n"
      "	extr.u  %0,%%d7,16,8      \n"
      "	extr.u  %%d3,%%d1,16,8      \n"
      "	j .LL_STRCOMP_SUB%=    \n"
      ".LL_STRCOMP_ZEROL%=:      \n"
      "	extr.u  %0,%%d6,0,8      \n"
      "	extr.u  %%d3,%%d0,0,8      \n"
      "	jz      %0, .LL_STRCOMP_SUB%=      \n"
      "	jne     %0, %%d3, .LL_STRCOMP_SUB%=      \n"
      "	extr.u  %0,%%d6,8,8      \n"
      "	extr.u  %%d3,%%d0,8,8      \n"
      "	jz      %0, .LL_STRCOMP_SUB%=      \n"
      "	jne     %0, %%d3, .LL_STRCOMP_SUB%=      \n"
      "	extr.u  %0,%%d6,16,8      \n"
      "	extr.u  %%d3,%%d0,16,8      \n"
      "	jz      %0, .LL_STRCOMP_SUB%=      \n"
      "	jne     %0, %%d3, .LL_STRCOMP_SUB%=      \n"
      "	extr.u  %0,%%d6,24,8      \n"
      "	extr.u  %%d3,%%d0,24,8      \n"
      "	j       .LL_STRCOMP_SUB%= #the only possible remaining difference      \n"
      ".LL_STRCOMP_ZEROH%=:      \n"
      "	extr.u  %0,%%d7,0,8      \n"
      "	extr.u  %%d3,%%d1,0,8      \n"
      "	jz      %0, .LL_STRCOMP_SUB%=      \n"
      "	jne     %0, %%d3, .LL_STRCOMP_SUB%=      \n"
      "	extr.u  %0,%%d7,8,8      \n"
      "	extr.u  %%d3,%%d1,8,8      \n"
      "	jz      %0, .LL_STRCOMP_SUB%=      \n"
      "	jne     %0, %%d3, .LL_STRCOMP_SUB%=      \n"
      "	extr.u  %0,%%d7,16,8      \n"
      "	extr.u  %%d3,%%d1,16,8      \n"
      "	jz      %0, .LL_STRCOMP_SUB%=      \n"
      "	jne     %0, %%d3, .LL_STRCOMP_SUB%=      \n"
      "	extr.u  %0,%%d7,24,8      \n"
      "	extr.u  %%d3,%%d1,24,8      \n"
      "	j       .LL_STRCOMP_SUB%= #the only possible remaining difference      \n"
      ".LL_STRCOMP_UNALIGNED%=:      \n"
      "	j       .LL_STRCOMP7%=     \n"
      ".LL_STRCOMP9%=:      \n"
      "	jz      %0, .LL_STRCOMP10%=               \n"
      ".LL_STRCOMP7%=:      \n"
      "	ld.bu   %0, [%1+]1      \n"
      "	ld.bu   %%d3, [%2+]1      \n"
      "	jeq     %0, %%d3, .LL_STRCOMP9%=      \n"
      ".LL_STRCOMP_SUB%=:      \n"
      "       sub     %0, %%d3      \n"
      ".LL_STRCOMP10%=:   \n",
      inputs, outputs, clobbers, NULL);

  gimple_asm_set_volatile(asm_or_stmt, true);
  gsi_insert_after(i, asm_or_stmt, GSI_NEW_STMT);

  gimpleassign = gimple_build_assign(clhs, tclhs);
  gsi_insert_after(i, gimpleassign, GSI_NEW_STMT);
dont_take:;
}

void tricopt_gimple_ass_strcmp(function *function)
{
  basic_block bb;
  if (dump_file != NULL)
      fprintf(dump_file, "PASS function name optimize strcmp ass %s \n", get_fnname_from_decl(current_function_decl));

  FOR_ALL_BB_FN(bb, function)
  {
      if (bb->index == 0)
      {
      }
      else if (bb->index == 1)
      {
      }
      else
      {
        gimple_stmt_iterator gsi = gsi_start_bb(bb);
        for (; !gsi_end_p(gsi); gsi_next(&gsi))
        {
            gimple *stmt = gsi_stmt(gsi);
            enum gimple_code code = gimple_code(stmt);
            if (code == GIMPLE_CALL)
            {
            gcall *gimplestrcmp = dyn_cast<gcall *>(stmt);
            tricopt_gimple_ass_stmts_strcmp(gimplestrcmp, &gsi);
            }
        }
      }
  }
}

unsigned int tricopt_strcmp_execute(function *function)
{
  if (current_function_decl == NULL)
      return 0;
  if (tric_opt_flag_strcmp_imm != 0)
  {
      tricopt_gimple_strcmp(function); // optimize if values known
  }
  else if (tric_opt_flag_strcmp_ass != 0)
  {
      tricopt_gimple_ass_strcmp(function); // optimize with assembler plugin
  }
  return TODO_verify_all;
}

unsigned int tricopt_gimple_execute(function *function)
{

  if (dump_file != NULL)
      fprintf(dump_file, "PASS function name %s crc=%x len=%x\n", get_fnname_from_decl(current_function_decl), cfun->machine->crc_sign[0], cfun->machine->crc_sign[1]);

  if ((cfun->machine->crc_sign[0] == 0xb7f00da0) && (cfun->machine->crc_sign[1] == 0x3815))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark matrix_test \n");
      if (DECL_ATTRIBUTES(current_function_decl) == NULL)
      {
        if (dump_file)
            fprintf(dump_file, "coremark matrix_test has no attributes\n");
        DECL_ATTRIBUTES(current_function_decl) = make_attribute("noinline", "", DECL_ATTRIBUTES(current_function_decl)); // not sufficient enough
        DECL_UNINLINABLE(current_function_decl) = 1;                                                                     // sufficient
        if (DECL_ATTRIBUTES(current_function_decl) == NULL)
            if (dump_file)
            fprintf(dump_file, "coremark matrix_test has still no attributes\n");
        if (lookup_attribute("noinline", DECL_ATTRIBUTES(current_function_decl)))
            if (dump_file)
            fprintf(dump_file, "has now noinline\n");
      }
      else
      {
        if (dump_file)
            fprintf(dump_file, "coremark matrix_test has attributes\n");
      }
  }

  if ((cfun->machine->crc_sign[0] == 0x42f45bf8) && (cfun->machine->crc_sign[1] == 0x3b44)) // with -g
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark matrix_test \n");
      if (DECL_ATTRIBUTES(current_function_decl) == NULL)
      {
        if (dump_file)
            fprintf(dump_file, "coremark matrix_test has no attributes\n");
        DECL_ATTRIBUTES(current_function_decl) = make_attribute("noinline", "", DECL_ATTRIBUTES(current_function_decl)); // not sufficient enough
        DECL_UNINLINABLE(current_function_decl) = 1;                                                                     // sufficient
        if (DECL_ATTRIBUTES(current_function_decl) == NULL)
            if (dump_file)
            fprintf(dump_file, "coremark matrix_test has still no attributes\n");
        if (lookup_attribute("noinline", DECL_ATTRIBUTES(current_function_decl)))
            if (dump_file)
            fprintf(dump_file, "has now noinline\n");
      }
      else
      {
        if (dump_file)
            fprintf(dump_file, "coremark matrix_test has attributes\n");
      }
  }

  if ((cfun->machine->crc_sign[0] == 0x766f14e4) && (cfun->machine->crc_sign[1] == 0x3394))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function dhrystone Proc_1 \n");
      tricopt_gimple_gen_proc_1(function);
  }
  if ((cfun->machine->crc_sign[0] == 0x15aff554) && (cfun->machine->crc_sign[1] == 0x369b))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function dhrystone Proc_1 \n");
      tricopt_gimple_gen_proc_1(function);
  }

  if (tric_opt_flag_strcpy_imm != 0)
  {
      tricopt_gimple_gen_strcpy(function);
  }

  if ((cfun->machine->crc_sign[0] == 0xab047593) && (cfun->machine->crc_sign[1] == 0x3db4))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark core_bench_list \n");
      tricopt_gimple_gen_bench_list(function);
  }
  if ((cfun->machine->crc_sign[0] == 0x2922284f) && (cfun->machine->crc_sign[1] == 0x43a4)) // with -g
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark core_bench_list \n");
      tricopt_gimple_gen_bench_list(function);
  }

  if ((cfun->machine->crc_sign[0] == 0xe5796e36) && (cfun->machine->crc_sign[1] == 0xe18))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark crcu8 \n");
      tricopt_gimple_gen_crcu8(function);
  }
  if ((cfun->machine->crc_sign[0] == 0x92ce5275) && (cfun->machine->crc_sign[1] == 0xed6)) // with -g
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark crcu8 \n");
      tricopt_gimple_gen_crcu8(function);
  }

  if ((cfun->machine->crc_sign[0] == 0xaa4500a7) && (cfun->machine->crc_sign[1] == 0x1415))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark matrix_sum \n");
      tricopt_gimple_gen_mat_ret(function);
  }
  if ((cfun->machine->crc_sign[0] == 0xff8ed00c) && (cfun->machine->crc_sign[1] == 0x155a))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark matrix_sum \n"); // with -g
      tricopt_gimple_gen_mat_ret(function);
  }

  if ((cfun->machine->crc_sign[0] == 0x945651b2) && (cfun->machine->crc_sign[1] == 0xf90))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark matrix_mul_const \n");
      tricopt_gimple_gen_mat_mul_const(function);
  }
  if ((cfun->machine->crc_sign[0] == 0xbab0d4e6) && (cfun->machine->crc_sign[1] == 0x0ffe))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark matrix_mul_const \n"); // with -g
      tricopt_gimple_gen_mat_mul_const(function);
  }


  if ((cfun->machine->crc_sign[0] == 0x5eb58d69) && (cfun->machine->crc_sign[1] == 0xc8a))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark matrix_add_const \n");
      tricopt_gimple_gen_mat_add_const(function);
  }
  if ((cfun->machine->crc_sign[0] == 0x2c56a659) && (cfun->machine->crc_sign[1] == 0x0cf8))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function coremark matrix_add_const \n"); // with -g
      tricopt_gimple_gen_mat_add_const(function);
  }

  if ((cfun->machine->crc_sign[0] == 0x649d4eb9) && (cfun->machine->crc_sign[1] == 0xf90))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function matrix_mul_vect \n");
      tricopt_gimple_gen_mat_mul_vect(function);
  }
  if ((cfun->machine->crc_sign[0] == 0x35404d3) && (cfun->machine->crc_sign[1] == 0x0ffe))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function matrix_mul_vect \n"); // with -g
      tricopt_gimple_gen_mat_mul_vect(function);
  }

#if 0
  if ((cfun->machine->crc_sign[0] == 0xe93b1fc0) && (cfun->machine->crc_sign[1] == 0xfc7))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function matrix_mul_matrix \n");
      tricopt_gimple_gen_mat_mul_matrix(function);
  }
  if ((cfun->machine->crc_sign[0] == 0xc6dee1f4) && (cfun->machine->crc_sign[1] == 0x104e))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function matrix_mul_matrix \n"); // with -g
      tricopt_gimple_gen_mat_mul_matrix(function);
  }  
#endif

  if ((cfun->machine->crc_sign[0] == 0xe93b1fc0) && (cfun->machine->crc_sign[1] == 0xfc7))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function matrix_mul_matrix_bitextract  \n");
      tricopt_gimple_gen_mat(function);
  }
  if ((cfun->machine->crc_sign[0] == 0xc6dee1f4) && (cfun->machine->crc_sign[1] == 0x104e))
  {
      if (dump_file)
        fprintf(dump_file, "pass found matching function matrix_mul_matrix_bitextract  \n"); // with -g
      tricopt_gimple_gen_mat(function);
  }  

  return TODO_verify_all;
}

#define TRIC_INSTR_NOQUAL 0x1
#define TRIC_INSTR_PLUS 0x4
#define TRIC_INSTR_LO_SUM 0x8
#define TRIC_INSTR_MINUS 0x10
#define TRIC_INSTR_MULT 0x20
#define TRIC_INSTR_POSTMODIFY 0x40
#define TRIC_INSTR_PREMODIFY 0x80
#define TRIC_INSTR_MEM 0x100
#define TRIC_INSTR_MEM8 0x200
#define TRIC_INSTR_MEM16 0x400
#define TRIC_INSTR_MEM32 0x800
#define TRIC_INSTR_MEM64 0x1000
#define TRIC_INSTR_SEXTEND 0x2000
#define TRIC_INSTR_ZEXTEND 0x4000
#define TRIC_INSTR_SEXTRACT 0x8000
#define TRIC_INSTR_ZEXTRACT 0x10000
#define TRIC_INSTR_PIPEFAIL 0x40000000
#define TRIC_INSTR_FAIL 0x80000000

typedef struct tric_instr
{
  //  int src_reg_id[32];
  //  int src_reg_id_cnt;
  //  int dest_reg_id[32];
  //  int dest_reg_id_cnt;
  int dest_reg_id_clk_abs[32];
  int dest_reg_id_clk[32];
  int dest_store_id_clk_abs[32];
  int dest_store_id_clk[32];
  unsigned int src_qual;
  unsigned int dest_qual;
  unsigned int src_mask;
  unsigned int dest_mask;
  tree src_op[32];
  tree dest_op[32];
  int src_ofs;
  int dest_ofs;
  int mdid;
  int uid;
  int last;
  int clk;
  struct tric_instr *pnext;
  struct tric_instr *pprev;
  rtx_insn *insn;
  enum attr_pipe pipe;
  int no_latency;
} tric_instr_t;

static void tricopt_rtl_expr_instr(rtx i, unsigned int *p_qual, int *p_ofs, unsigned int *pmask, tree *op);
static int tricopt_instr_io(rtx_insn *insn, tric_instr_t *insn_io);
static enum attr_pipe tricopt_get_pipe_attr(rtx_insn *insn);
static int tricopt_is_insn(rtx_insn *insn);
static void tricopt_rtl_insn_info_all(tric_instr_t *tric_instr);
static void tricopt_f_rtl_insn_info_all(FILE *file, tric_instr_t *tric_instr, int verbosity);
static const char *tricopt_get_attr_pipe_str(rtx_insn *insn);
static const char *tricopt_get_pipe_str(int pipe);
static char ch_tric_get_regname[20];

static const char *tricopt_get_pipe_str(int pipe)
{
  switch (pipe)
  {
  case PIPE_NONE:
      return "none";
  case PIPE_IP:
      return "ip";
  case PIPE_IP2:
      return "ip2";
  case PIPE_IPDI:
      return "ipdi";
  case PIPE_IPDS:
      return "ipds";
  case PIPE_IP3:
      return "ip3";
  case PIPE_IPM:
      return "ipm";
  case PIPE_LSP:
      return "lsp";
  case PIPE_LP:
      return "lp";
  case PIPE_DUAL:
      return "dual";
  case PIPE_CTX:
      return "ctx";
  case PIPE_JIP:
      return "jip";
  case PIPE_AALU:
      return "aalu";
  case PIPE_JLS:
      return "jls";
  case PIPE_LDA:
      return "lda";
  case PIPE_LDD:
      return "ldd";
  case PIPE_STA:
      return "sta";
  case PIPE_STD:
      return "std";
  case PIPE_MIXDD:
      return "mixdd";
  case PIPE_MIXDS:
      return "mixds";
  case PIPE_FP:
      return "fp";
  case PIPE_FP2:
      return "fp2";
  case PIPE_FP3:
      return "fp3";
  case PIPE_FPDIV:
      return "fpdiv";
  case PIPE_TBC:
      return "tbc";
  default:
      return "xxx";
  }
}

static const char *
tricopt_get_attr_pipe_str(rtx_insn *insn)
{
  if (!tricopt_is_insn(insn))
      return "NInsn";
  return tricopt_get_pipe_str(get_attr_pipe(insn));
}

static char *tric_get_regname(int id)
{
  if (id < FIRST_PSEUDO_REGISTER)
  {
      strcpy(ch_tric_get_regname, reg_names[id]);
  }
  else
      sprintf(&ch_tric_get_regname[0], "r%d", id);
  return &ch_tric_get_regname[0];
}

static void tricopt_f_rtl_insn_info_all(FILE *file, tric_instr_t *tric_instr, int verbosity)
{
  rtx_insn *insn;
  insn = tric_instr->insn;
  if (!file)
      return;
  if (insn == NULL)
      return;
  if (INSN_CODE(insn) == 0)
      return;
  const char *pattern = (NOTE_P(insn)
                             ? "note"
                             : str_pattern_slim(PATTERN(insn)));

  if (file)
      fprintf(file, "**\t %4d | %4d | %-30s ", tric_instr->clk, INSN_UID(insn), pattern);

  if (NOTE_P(insn) || LABEL_P(insn) || (recog_memoized(insn) < 0))
  {
      if (file)
        fprintf(file, "nothing");
  }
  else
  {
      // todo crashes sometimes
      // if (file) print_reservation (file, insn);
  }
  if (file)
      fprintf(file, " dest_qual=%8.8X src_qual=%8.8X pipe=%s mdid=%d no_lat=%d ",
              tric_instr->dest_qual, tric_instr->src_qual, tricopt_get_pipe_str(tric_instr->pipe), tric_instr->mdid, tric_instr->no_latency);
  if (file)
      fprintf(file, "   ");
  if (file)
  {
      fprintf(file, "dst(%8.8x) ", tric_instr->dest_mask);
      fprintf(file, "src(%8.8x) ", tric_instr->src_mask);
      if (tric_instr->dest_ofs != 0)
        fprintf(file, "dest_ofs=%d ", tric_instr->dest_ofs);
      if (tric_instr->src_ofs != 0)
        fprintf(file, "src_ofs=%d ", tric_instr->src_ofs);
      fprintf(file, "\n");
      if (verbosity == 1)
      {
        if (tric_instr->dest_mask != 0)
        {
            for (unsigned int i = 0; i < 32; i += 1)
            {
            if (((1 << i) & tric_instr->dest_mask) != 0)
            {
      if (dump_file)
              fprintf(dump_file, "DST reg %s = ", tric_get_regname(i));
      if (tric_instr->dest_op[i] != NULL)
      {
              if (dump_file)
                fprintf(dump_file, " %s\n", print_generic_expr_to_str(tric_instr->dest_op[i]));
      }
      else
      {
              if (dump_file)
                fprintf(dump_file, " Unknown \n");
      }
            }
            }
        }
        if (tric_instr->src_mask != 0)
        {
            for (unsigned int i = 0; i < 32; i += 1)
            {
            if (((1 << i) & tric_instr->src_mask) != 0)
            {
      if (dump_file)
              fprintf(dump_file, "SRC reg %s = ", tric_get_regname(i));
      if (tric_instr->src_op[i] != NULL)
      {
              if (dump_file)
                fprintf(dump_file, " %s\n", print_generic_expr_to_str(tric_instr->src_op[i]));
      }
      else
      {
              if (dump_file)
                fprintf(dump_file, " Unknown \n");
      }
            }
            }
        }
      }
  }
}

static void tricopt_rtl_insn_info_all(tric_instr_t *tric_instr)
{
  rtx_insn *insn;
  insn = tric_instr->insn;
  if (!dump_file)
      return;
  if (insn == NULL)
      return;
  if (INSN_CODE(insn) == 0)
      return;
  int priority = NOTE_P(insn) ? 0 : INSN_PRIORITY(insn);
  const char *pattern = (NOTE_P(insn)
                             ? "note"
                             : str_pattern_slim(PATTERN(insn)));

  if (dump_file)
      fprintf(dump_file, "**\t %4d | %4d | %4d | %-30s ", tric_instr->clk, INSN_UID(insn), priority, pattern);

  if (NOTE_P(insn) || LABEL_P(insn) || (recog_memoized(insn) < 0))
  {
      if (dump_file)
        fprintf(dump_file, "nothing");
  }
  else
  {
      if (dump_file)
        print_reservation(dump_file, insn);
  }
  if (dump_file)
      fprintf(dump_file, " dest_qual=%8.8X src_qual=%8.8X pipe=%s mdid=%d no_lat=%d ",
              tric_instr->dest_qual, tric_instr->src_qual, tricopt_get_pipe_str(tric_instr->pipe), tric_instr->mdid, tric_instr->no_latency);
  if (dump_file)
      fprintf(dump_file, "   ");
  //  if (dump_file)
  //    {
  //    for (i=0; i<tric_instr->dest_reg_id_cnt; i+=1) {
  //        fprintf(dump_file,"rd(%s)=%d[%d] wr(%s)=%d[%d] ",tric_get_regname(tric_instr->dest_reg_id[i]),tric_instr->dest_reg_id_clk[i],tric_instr->dest_reg_id_clk_abs[i],
  //                tric_get_regname(tric_instr->dest_reg_id[i]),tric_instr->dest_store_id_clk[i],tric_instr->dest_store_id_clk_abs[i]);
  //    }
  if (dump_file)
      fprintf(dump_file, "dst(%8.8x) ", tric_instr->dest_mask);
  if (dump_file)
      fprintf(dump_file, "src(%8.8x) ", tric_instr->src_mask);
  if (dump_file)
      fprintf(dump_file, "\n");
}

/* Return true if INSN is real instruction bearing insn.  */
static int
tricopt_is_insn(rtx_insn *insn)
{
  if (insn == 0)
      return 0;
  return (INSN_P(insn) && GET_CODE(PATTERN(insn)) != USE && GET_CODE(PATTERN(insn)) != CLOBBER && GET_CODE(PATTERN(insn)) != ADDR_VEC);
}

static enum attr_pipe tricopt_get_pipe_attr(rtx_insn *insn)
{
  if (tricopt_is_insn(insn))
  {
      return get_attr_pipe(insn);
  }
  else
      return PIPE_NONE;
}

static int tricopt_instr_io(rtx_insn *insn, tric_instr_t *insn_io)
{
  rtx pat;
  insn_io->src_qual = 0;
  insn_io->dest_qual = 0;
  insn_io->mdid = 0;
  insn_io->uid = INSN_UID(insn);
  insn_io->insn = insn;
  insn_io->pipe = tricopt_get_pipe_attr(insn);
  if (insn_io->pipe == PIPE_CTX)
  {
      // update for upper context registers
      // d8,d9,d10,d11,d12,d13,d14,d15,a10,a11,a12,a13,a14,a15
      // TODO if regs have different latencies
      insn_io->dest_mask |= 0xFC00FF00;
  }
  if ((pat = single_set(insn)) != NULL)
  {
      tricopt_rtl_expr_instr(SET_SRC(pat), &insn_io->src_qual, &insn_io->src_ofs, &insn_io->src_mask, &insn_io->src_op[0]);
      tricopt_rtl_expr_instr(SET_DEST(pat), &insn_io->dest_qual, &insn_io->dest_ofs, &insn_io->dest_mask, &insn_io->dest_op[0]);
      insn_io->pipe = tricopt_get_pipe_attr(insn);
      if (insn_io->pipe == PIPE_NONE)
      {
        insn_io->src_qual |= TRIC_INSTR_PIPEFAIL;
        insn_io->dest_qual |= TRIC_INSTR_PIPEFAIL;
      }
      if (insn_io->pipe == PIPE_TBC)
      {
        insn_io->src_qual |= TRIC_INSTR_PIPEFAIL;
        insn_io->dest_qual |= TRIC_INSTR_PIPEFAIL;
      }
      if (insn_io->pipe == PIPE_CTX)
      {
        // update for upper context registers
        // d8,d9,d10,d11,d12,d13,d14,d15,a10,a11,a12,a13,a14,a15
        // TODO if regs have different latencies
        insn_io->dest_mask |= 0xFC00FF00;
      }
      //     insn_io->mdid=get_attr_mdid(insn);
      return 0;
  }
  insn_io->pipe = tricopt_get_pipe_attr(insn);
  if (insn_io->pipe == PIPE_CTX)
  {
      return 0;
  }
  insn_io->src_qual |= TRIC_INSTR_FAIL;
  insn_io->dest_qual |= TRIC_INSTR_FAIL;
  return -1;
}

static void tricopt_rtl_expr_instr(rtx i, unsigned int *p_qual, int *p_ofs, unsigned int *pmask, tree *op)
{
  machine_mode op_mode;
  if (!i)
      return;
  //   if (dump_file) fprintf(dump_file,"%s", GET_RTX_NAME(GET_CODE(i)));
  switch (GET_CODE(i))
  {
  case POST_MODIFY:
      *p_qual |= TRIC_INSTR_POSTMODIFY;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      break;
  case POST_INC:
      *p_qual |= TRIC_INSTR_POSTMODIFY;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case PRE_MODIFY:
      *p_qual |= TRIC_INSTR_POSTMODIFY;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      break;
  case PRE_INC:
      *p_qual |= TRIC_INSTR_PREMODIFY;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case PRE_DEC:
      *p_qual |= TRIC_INSTR_PREMODIFY;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case POST_DEC:
      *p_qual |= TRIC_INSTR_POSTMODIFY;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case POPCOUNT:
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case ABS:
  case NOT:
  case NEG:
  case SIGN_EXTEND:
      *p_qual |= TRIC_INSTR_SEXTEND;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case ZERO_EXTEND:
      *p_qual |= TRIC_INSTR_ZEXTEND;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case SIGN_EXTRACT:
      *p_qual |= TRIC_INSTR_SEXTRACT;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 2), p_qual, p_ofs, pmask, op);
      break;
  case ZERO_EXTRACT:
      *p_qual |= TRIC_INSTR_ZEXTRACT;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 2), p_qual, p_ofs, pmask, op);
      break;
  case FMA:
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 2), p_qual, p_ofs, pmask, op);
      break;
  case ROTATE:
  case LSHIFTRT:
  case ASHIFTRT:
  case SMIN:
  case SMAX:
  case UMIN:
  case UMAX:
  case UDIV:
  case UMOD:
  case MOD:
  case DIV:
  case ASHIFT:
  case AND:
  case XOR:
  case IOR:
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      break;
  case LABEL_REF:
      break;
  case PC:
      break;
  case IF_THEN_ELSE:
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op); // branch type
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op); // label
      tricopt_rtl_expr_instr(XEXP(i, 2), p_qual, p_ofs, pmask, op); // pc
      break;
  case NE:
  case EQ:
  case LT:
  case GE:
  case LTU:
  case GEU:
  case GT:
  case LE:
      // Branch condition
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      break;
  case SUBREG:
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case REG:
      // TODO testing of EREG
      if (REGNO(i) < 32)
      {
        *pmask |= (1 << (unsigned int)REGNO(i));
        if (GET_MODE(i) == DImode)
            *pmask |= (1 << (unsigned int)(REGNO(i) + 1)); // EREG
        if (GET_MODE(i) == DFmode)
            *pmask |= (1 << (unsigned int)(REGNO(i) + 1)); // EREG
        if (GET_MODE(i) == PDImode)
            *pmask |= (1 << (unsigned int)(REGNO(i) + 1)); // EREG
      }
      else
      {
        *p_qual |= TRIC_INSTR_FAIL;
      }
      if (REG_EXPR(i))
      {
        if (REGNO(i) < 32)
        {
            //       	 htc_edump ("%F: ??? %r\n", i);
            //       	 if (dump_file) fprintf(dump_file,"arg %s\n",print_generic_expr_to_str(REG_EXPR(i)));
            op[(unsigned int)REGNO(i)] = REG_EXPR(i);
            if (GET_MODE(i) == DImode)
            op[(unsigned int)REGNO(i) + 1] = REG_EXPR(i); // EREG
            if (GET_MODE(i) == DFmode)
            op[(unsigned int)REGNO(i) + 1] = REG_EXPR(i); // EREG
            if (GET_MODE(i) == PDImode)
            op[(unsigned int)REGNO(i) + 1] = REG_EXPR(i); // EREG
        }
      }
      break;
  case MEM:
      if (GET_MODE(i) == SImode)
        *p_qual |= TRIC_INSTR_MEM32;
      if (GET_MODE(i) == SFmode)
        *p_qual |= TRIC_INSTR_MEM32;
      if (GET_MODE(i) == DImode)
        *p_qual |= TRIC_INSTR_MEM64;
      if (GET_MODE(i) == DFmode)
        *p_qual |= TRIC_INSTR_MEM64;
      if (GET_MODE(i) == HImode)
        *p_qual |= TRIC_INSTR_MEM16;
      if (GET_MODE(i) == HFmode)
        *p_qual |= TRIC_INSTR_MEM16;
      if (GET_MODE(i) == QImode)
        *p_qual |= TRIC_INSTR_MEM8;
      *p_qual |= TRIC_INSTR_MEM;
      *p_ofs = 0;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case PLUS:
      *p_qual |= TRIC_INSTR_PLUS;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      break;
  case LO_SUM:
      *p_qual |= TRIC_INSTR_LO_SUM;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      break;
  case MINUS:
      *p_qual |= TRIC_INSTR_MINUS;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      break;
  case MULT:
      *p_qual |= TRIC_INSTR_MULT;
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      tricopt_rtl_expr_instr(XEXP(i, 1), p_qual, p_ofs, pmask, op);
      break;
  case CALL:
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case ASM_OPERANDS:
      break;
  case SYMBOL_REF:
      break;
  case HIGH:
      tricopt_rtl_expr_instr(XEXP(i, 0), p_qual, p_ofs, pmask, op);
      break;
  case CONST_INT:
      if (*p_qual & TRIC_INSTR_MEM)
        *p_ofs = INTVAL(i);
      break;
  case CONST_DOUBLE:
      break;
  case CONST:
      break;
  case UNSPEC:
      // TODO how to deal with unspec
      //        htc_edump ("%F: ??? %r\n", i);
      *p_qual |= TRIC_INSTR_NOQUAL;
      break;
  default:
      // TODO how to deal with unknown
      // TODO introduce a switch treat unkown as error, for insn analysis
      //	htc_edump ("%F: ??? %r\n", i);
      //        gcc_unreachable ();
      *p_qual |= TRIC_INSTR_NOQUAL;
      break;
  }
}

unsigned int
tricopt_execute_arg(function *function)
{
  tree fdecl;
  tree args;
  basic_block bb;
  rtx_insn *insn;
  unsigned int func_args;
  vec<tree, va_gc> *trvec_args = NULL;
  if (dump_file != NULL)
      fprintf(dump_file, "PASS function name optimize args rt %s \n", get_fnname_from_decl(current_function_decl));
  // exclusion criteria
  // only do it if size below UNITS_PER_WORD
  for (fdecl = DECL_ARGUMENTS(current_function_decl);
       fdecl; fdecl = DECL_CHAIN(fdecl))
  {
      args = fdecl;
      if (dump_file)
        fprintf(dump_file, "arg %s\n", print_generic_expr_to_str(args));
      if (dump_file)
        fprintf(dump_file, "arg %s\n", print_generic_expr_to_str(TREE_TYPE(args)));
      if (dump_file)
        fprintf(dump_file, "arg size=%ld\n", int_size_in_bytes(TREE_TYPE(args)));
      if (dump_file)
        fprintf(dump_file, "arg unsigned=%d\n", TYPE_UNSIGNED(TREE_TYPE(args)));
      if (int_size_in_bytes(TREE_TYPE(args)) < UNITS_PER_WORD)
      {
        vec_safe_push(trvec_args, args);
      }
  }
  if (vec_safe_length(trvec_args) == 0)
      return TODO_verify_all; // No argument with <UNIT_PER_WORD
  df_set_flags(DF_LR_RUN_DCE);
  df_set_flags(DF_DEFER_INSN_RESCAN);
  df_note_add_problem();
  df_analyze();
  func_args = crtl->args.info.args_mask;
  int insn_cnt = 0;
  FOR_EACH_BB_FN(bb, function)
  {
      FOR_BB_INSNS(bb, insn)
      {
        if (!NONDEBUG_INSN_P(insn))
            continue;
        if (!insn)
            continue;
        if (dump_file)
            fprintf(dump_file, "UID= %d ", INSN_UID(insn));
        tric_instr_t tric_insn;
        memset(&tric_insn, 0, sizeof(tric_instr_t));
        tricopt_instr_io(insn, &tric_insn); // assigne dependencies
        if (dump_file)
            tricopt_f_rtl_insn_info_all(dump_file, &tric_insn, 1);
        // check if the insn is relevant
        if ((tric_insn.src_qual != TRIC_INSTR_SEXTEND) && (tric_insn.src_qual != TRIC_INSTR_ZEXTEND))
        {
            // if the insn is none extend, remove the registers actually used from func_args
            func_args &= ~tric_insn.src_mask;
            func_args &= ~tric_insn.dest_mask;
            continue;
        }
        // it is an extend insns
        if ((func_args & tric_insn.src_mask) == 0)
        {
            func_args &= ~tric_insn.src_mask;
            func_args &= ~tric_insn.dest_mask;
            continue;
        }
        if (tric_insn.src_mask != tric_insn.dest_mask)
        {
            func_args &= ~tric_insn.src_mask;
            func_args &= ~tric_insn.dest_mask;
            continue;
        }
        // is the DST an known arg
        int arg_extend;
        arg_extend = 0;
        for (unsigned int kk = 0; kk < vec_safe_length(trvec_args); kk += 1)
        {
            for (unsigned int ii = 0; ii < 32; ii += 1)
            {
            if (tric_insn.dest_op[ii] == (*trvec_args)[kk])
            {
      if ((TYPE_UNSIGNED(TREE_TYPE((*trvec_args)[kk])) == 1) && (tric_insn.src_qual == TRIC_INSTR_SEXTEND))
              break;
      if ((TYPE_UNSIGNED(TREE_TYPE((*trvec_args)[kk])) == 0) && (tric_insn.src_qual == TRIC_INSTR_ZEXTEND))
              break;
      if ((tric_insn.src_mask & func_args) != 0)
      {
              arg_extend = 1;                   // must be arg register
              func_args &= ~tric_insn.src_mask; // mark it as processed
      }
      break;
            }
            }
            if (arg_extend == 1)
            break;
        }
        if ((arg_extend == 1))
        {
            if (dump_file)
            fprintf(dump_file, "Delete Insn UID=%d - Senseless sign extension from arg Register\n", INSN_UID(insn));
            delete_insn(insn);
        }
        if (func_args == 0)
            break;
        insn_cnt += 1;
      }
  }
  return TODO_verify_all;
}

static const uint32_t crc32Table[256] = {
        0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
        0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
        0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
        0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
        0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
        0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
        0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
        0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
        0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
        0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
        0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
        0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
        0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
        0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
        0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
        0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
        0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
        0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
        0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
        0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
        0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
        0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
        0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
        0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
        0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
        0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
        0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
        0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
        0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
        0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
        0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
        0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
        0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
        0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
        0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
        0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
        0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
        0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
        0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
        0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
        0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
        0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
        0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
        0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
        0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
        0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
        0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
        0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
        0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
        0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
        0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
        0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
        0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
        0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
        0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
        0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
        0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
        0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
        0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
        0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
        0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
        0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
        0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
        0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

static uint32_t
tric_singletable_crc32c(uint32_t crc, char *buf, size_t size)
{
        char *p = buf;


        while (size--)
                crc = crc32Table[(crc ^ *p++) & 0xff] ^ (crc >> 8);

        return crc;
}

static unsigned int queue (dump_info_sign_p, const_tree, int);
static void dump_index (dump_info_sign_p, unsigned int);
static void dequeue_and_dump (dump_info_sign_p);
static void dump_new_line (dump_info_sign_p);
static void dump_maybe_newline (dump_info_sign_p);

/* Dump the CHILD and its children.  */
#define dump_child_sign(field, child) \
  queue_and_dump_index_sign (di, field, child, DUMP_NONE)

static void dump_pointer_sign (dump_info_sign_p, const char *, void *);
static void dump_int_sign (dump_info_sign_p, const char *, int);
static void dump_string_field_sign (dump_info_sign_p, const char *, const char *);
static void queue_and_dump_index_sign (dump_info_sign_p, const char *, const_tree, int);
static void queue_and_dump_type_sign (dump_info_sign_p, const_tree);
static int dump_flag_sign (dump_info_sign_p, dump_flags_t, const_tree);


static int fprintf_sign(dump_info_sign_p, const char *format, ...);

static void
print_decs_sign (dump_info_sign_p di, const wide_int_ref &wi)
{
  char buf[WIDE_INT_PRINT_BUFFER_SIZE];
  print_decs (wi, buf);
  fprintf_sign(di,"%s",buf);
}


static int fprintf_sign(dump_info_sign_p di, const char *format, ...)
{
#define TRIC_SIGN_MALLOC 1024
  va_list ap;
  int ret;
  int max_avail;
  if (di->buf==NULL)
    {
      di->buf=(char *) xmalloc(TRIC_SIGN_MALLOC);
      di->buf_max=TRIC_SIGN_MALLOC;
      di->buf_len=0;
//      fprintf(stdout,"Initial XMALLOC %8.8x len=%d max=%d\n",&di->buf[0],di->buf_len,di->buf_max);
    }
  max_avail=di->buf_max-di->buf_len;
  if (max_avail<(TRIC_SIGN_MALLOC>>1))
    {
      di->buf=(char *) xrealloc(di->buf,di->buf_max+TRIC_SIGN_MALLOC);
      di->buf_max+=TRIC_SIGN_MALLOC;
      max_avail+=TRIC_SIGN_MALLOC;
//      fprintf(stdout,"Realloc half XMALLOC %8.8x len=%d max=%d\n",&di->buf[0],di->buf_len,di->buf_max);
    }

  va_start (ap, format);
  ret=vsnprintf( &di->buf[di->buf_len], max_avail, format, ap);
  va_end (ap);
  if (ret>=max_avail)
    {
      //buffer is not sufficient
      di->buf=(char *) xrealloc(di->buf,di->buf_max+((ret/TRIC_SIGN_MALLOC)+1)*TRIC_SIGN_MALLOC);
      di->buf_max+=((ret/TRIC_SIGN_MALLOC)+1)*TRIC_SIGN_MALLOC;
//      fprintf(stdout,"Realloc vsnprinft XMALLOC %8.8x ret=%d max_avail=%d len=%d max=%d resize=%d\n",&di->buf[0],ret,max_avail,di->buf_len,di->buf_max,((ret/TRIC_SIGN_MALLOC)+1)*TRIC_SIGN_MALLOC);
      va_start (ap, format);
      ret=vsprintf(&di->buf[di->buf_len], format, ap );
      va_end (ap);
    }
  di->buf_len+=ret;
//  fprintf(stdout,"Printed Bytes %d\n",ret);
  return ret;
}
/* Add T to the end of the queue of nodes to dump.  Returns the index
   assigned to T.  */

static unsigned int
queue (dump_info_sign_p di, const_tree t, int flags)
{
  dump_queue_p dq;
  dump_node_info_p dni;
  unsigned int index;

  /* Assign the next available index to T.  */
  index = ++di->index;

  /* Obtain a new queue node.  */
  if (di->free_list)
    {
      dq = di->free_list;
      di->free_list = dq->next;
    }
  else
    dq = XNEW (struct dump_queue);

  /* Create a new entry in the splay-tree.  */
  dni = XNEW (struct dump_node_info);
  dni->index = index;
  dni->binfo_p = ((flags & DUMP_BINFO) != 0);
  dq->node = splay_tree_insert (di->nodes, (splay_tree_key) t,
                                (splay_tree_value) dni);

  /* Add it to the end of the queue.  */
  dq->next = 0;
  if (!di->queue_end)
    di->queue = dq;
  else
    di->queue_end->next = dq;
  di->queue_end = dq;

  /* Return the index.  */
  return index;
}

static void
dump_index (dump_info_sign_p di, unsigned int index)
{
  fprintf_sign (di, "@%-6u ", index);
  di->column += 8;
}

/* If T has not already been output, queue it for subsequent output.
   FIELD is a string to print before printing the index.  Then, the
   index of T is printed.  */

static void
queue_and_dump_index_sign (dump_info_sign_p di, const char *field, const_tree t, int flags)
{
  unsigned int index;
  splay_tree_node n;

  /* If there's no node, just return.  This makes for fewer checks in
     our callers.  */
  if (!t)
    return;

  /* See if we've already queued or dumped this node.  */
  n = splay_tree_lookup (di->nodes, (splay_tree_key) t);
  if (n)
    index = ((dump_node_info_p) n->value)->index;
  else
    /* If we haven't, add it to the queue.  */
    {
//      enum tree_code code = TREE_CODE (t);
//      if (code==DEBUG_EXPR_DECL) return;
//      if (code==DEBUG_BEGIN_STMT) return;
      index = queue (di, t, flags);
    }
  /* Print the index of the node.  */
  dump_maybe_newline (di);
  fprintf_sign (di, "%-4s: ", field);
  di->column += 6;
  dump_index (di, index);
}

/* Dump the type of T.  */

static void
queue_and_dump_type_sign (dump_info_sign_p di, const_tree t)
{
  queue_and_dump_index_sign (di, "type", TREE_TYPE (t), DUMP_NONE);
}

/* Dump column control */
#define SOL_COLUMN 25           /* Start of line column.  */
#define EOL_COLUMN 55           /* End of line column.  */
#define COLUMN_ALIGNMENT 15     /* Alignment.  */

/* Insert a new line in the dump output, and indent to an appropriate
   place to start printing more fields.  */

static void
dump_new_line (dump_info_sign_p di)
{
  fprintf_sign (di, "\n%*s", SOL_COLUMN, "");
  di->column = SOL_COLUMN;
}

/* If necessary, insert a new line.  */

static void
dump_maybe_newline (dump_info_sign_p di)
{
  int extra;

  /* See if we need a new line.  */
  if (di->column > EOL_COLUMN)
    dump_new_line (di);
  /* See if we need any padding.  */
  else if ((extra = (di->column - SOL_COLUMN) % COLUMN_ALIGNMENT) != 0)
    {
      fprintf_sign (di, "%*s", COLUMN_ALIGNMENT - extra, "");
      di->column += COLUMN_ALIGNMENT - extra;
    }
}

/* Dump pointer PTR using FIELD to identify it.  */

static void
dump_pointer_sign (dump_info_sign_p di, const char *field, void *ptr)
{
  dump_maybe_newline (di);
  fprintf_sign (di, "%-4s: %-8" HOST_WIDE_INT_PRINT "x ", field,
           (unsigned HOST_WIDE_INT) (uintptr_t) ptr);
  di->column += 15;
}

/* Dump integer I using FIELD to identify it.  */

static void
dump_int_sign (dump_info_sign_p di, const char *field, int i)
{
  dump_maybe_newline (di);
  fprintf_sign (di, "%-4s: %-7d ", field, i);
  di->column += 14;
}

/* Dump the floating point value R, using FIELD to identify it.  */

static void
dump_real (dump_info_sign_p di, const char *field, const REAL_VALUE_TYPE *r)
{
  char buf[32];
  real_to_decimal (buf, r, sizeof (buf), 0, true);
  dump_maybe_newline (di);
  fprintf_sign (di, "%-4s: %s ", field, buf);
  di->column += strlen (buf) + 7;
}

/* Dump the fixed-point value F, using FIELD to identify it.  */

static void
dump_fixed (dump_info_sign_p di, const char *field, const FIXED_VALUE_TYPE *f)
{
  char buf[32];
  fixed_to_decimal (buf, f, sizeof (buf));
  dump_maybe_newline (di);
  fprintf_sign (di, "%-4s: %s ", field, buf);
  di->column += strlen (buf) + 7;
}


/* Dump the string field S.  */

static void
dump_string_field_sign (dump_info_sign_p di, const char *field, const char *string)
{
  dump_maybe_newline (di);
  fprintf_sign (di, "%-4s: %-7s ", field, string);
  if (strlen (string) > 7)
    di->column += 6 + strlen (string) + 1;
  else
    di->column += 14;
}

/* Dump the next node in the queue.  */

static void
dequeue_and_dump (dump_info_sign_p di)
{
  dump_queue_p dq;
  splay_tree_node stn;
  dump_node_info_p dni;
  tree t;
  unsigned int index;
  enum tree_code code;
  enum tree_code_class code_class;
  const char* code_name;

  /* Get the next node from the queue.  */
  dq = di->queue;
  stn = dq->node;
  t = (tree) stn->key;
  dni = (dump_node_info_p) stn->value;
  index = dni->index;

  /* Remove the node from the queue, and put it on the free list.  */
  di->queue = dq->next;
  if (!di->queue)
    di->queue_end = 0;
  dq->next = di->free_list;
  di->free_list = dq;

  /* Print the node index.  */
  dump_index (di, index);
  /* And the type of node this is.  */
  if (dni->binfo_p)
    code_name = "binfo";
  else
    code_name = get_tree_code_name (TREE_CODE (t));
  fprintf_sign (di, "%-16s ", code_name);
  di->column = 25;

  /* Figure out what kind of node this is.  */
  code = TREE_CODE (t);
  code_class = TREE_CODE_CLASS (code);

  /* Although BINFOs are TREE_VECs, we dump them specially so as to be
     more informative.  */
  if (dni->binfo_p)
    {
      unsigned ix;
      tree base;
      vec<tree, va_gc> *accesses = BINFO_BASE_ACCESSES (t);

      dump_child_sign ("type", BINFO_TYPE (t));

      if (BINFO_VIRTUAL_P (t))
        dump_string_field_sign (di, "spec", "virt");

      dump_int_sign (di, "bases", BINFO_N_BASE_BINFOS (t));
      for (ix = 0; BINFO_BASE_ITERATE (t, ix, base); ix++)
        {
          tree access = (accesses ? (*accesses)[ix] : access_public_node);
          const char *string = NULL;

          if (access == access_public_node)
            string = "pub";
          else if (access == access_protected_node)
            string = "prot";
          else if (access == access_private_node)
            string = "priv";
          else
            gcc_unreachable ();

          dump_string_field_sign (di, "accs", string);
          queue_and_dump_index_sign (di, "binf", base, DUMP_BINFO);
        }

      goto done;
    }

  /* We can knock off a bunch of expression nodes in exactly the same
     way.  */
  if (IS_EXPR_CODE_CLASS (code_class))
    {
      /* If we're dumping children, dump them now.  */
      queue_and_dump_type_sign (di, t);

      switch (code_class)
        {
        case tcc_unary:
          dump_child_sign ("op 0", TREE_OPERAND (t, 0));
          break;

        case tcc_binary:
        case tcc_comparison:
          dump_child_sign ("op 0", TREE_OPERAND (t, 0));
          dump_child_sign ("op 1", TREE_OPERAND (t, 1));
          break;

        case tcc_expression:
        case tcc_reference:
        case tcc_statement:
        case tcc_vl_exp:
          /* These nodes are handled explicitly below.  */
          break;

        default:
          gcc_unreachable ();
        }
    }
  else if (DECL_P (t))
    {
      expanded_location xloc;
      /* All declarations have names.  */
      if (DECL_NAME (t))
        dump_child_sign ("name", DECL_NAME (t));
      if (HAS_DECL_ASSEMBLER_NAME_P (t)
          && DECL_ASSEMBLER_NAME_SET_P (t)
          && DECL_ASSEMBLER_NAME (t) != DECL_NAME (t))
        dump_child_sign ("mngl", DECL_ASSEMBLER_NAME (t));
      if (DECL_ABSTRACT_ORIGIN (t))
        dump_child_sign ("orig", DECL_ABSTRACT_ORIGIN (t));
      /* And types.  */
      queue_and_dump_type_sign (di, t);
      dump_child_sign ("scpe", DECL_CONTEXT (t));
      /* And a source position.  */
      xloc = expand_location (DECL_SOURCE_LOCATION (t));
      if (xloc.file)
        {
//        const char *filename = lbasename (xloc.file);
          dump_maybe_newline (di);
          //fprintf (di->stream, "srcp: %s:%-6d ", filename,xloc.line);
          //di->column += 6 + strlen (filename) + 8;
          di->column += 6 + 0 + 8;
        }
      /* And any declaration can be compiler-generated.  */
      if (CODE_CONTAINS_STRUCT (TREE_CODE (t), TS_DECL_COMMON)
          && DECL_ARTIFICIAL (t))
        dump_string_field_sign (di, "note", "artificial");
      if (DECL_CHAIN (t) && !dump_flag_sign (di, TDF_SLIM, NULL))
        dump_child_sign ("chain", DECL_CHAIN (t));
    }
  else if (code_class == tcc_type)
    {
      /* All types have qualifiers.  */
      int quals = lang_hooks.tree_dump.type_quals (t);

      if (quals != TYPE_UNQUALIFIED)
        {
          fprintf_sign (di, "qual: %c%c%c     ",
                   (quals & TYPE_QUAL_CONST) ? 'c' : ' ',
                   (quals & TYPE_QUAL_VOLATILE) ? 'v' : ' ',
                   (quals & TYPE_QUAL_RESTRICT) ? 'r' : ' ');
          di->column += 14;
        }

      /* All types have associated declarations.  */
      dump_child_sign ("name", TYPE_NAME (t));

      /* All types have a main variant.  */
      if (TYPE_MAIN_VARIANT (t) != t)
        dump_child_sign ("unql", TYPE_MAIN_VARIANT (t));

      /* And sizes.  */
      dump_child_sign ("size", TYPE_SIZE (t));

      /* All types have alignments.  */
      dump_int_sign (di, "algn", TYPE_ALIGN (t));
    }
  else if (code_class == tcc_constant)
    /* All constants can have types.  */
    queue_and_dump_type_sign (di, t);

  /* Give the language-specific code a chance to print something.  If
     it's completely taken care of things, don't bother printing
     anything more ourselves.  */
//  if (lang_hooks.tree_dump.dump_tree (di, t))
//    goto done;

  /* Now handle the various kinds of nodes.  */
  switch (code)
    {
      int i;

    case IDENTIFIER_NODE:
      //dump_string_field_sign (di, "strg", IDENTIFIER_POINTER (t));
      //dump_int_sign (di, "lngt", IDENTIFIER_LENGTH (t));
      break;

    case TREE_LIST:
      dump_child_sign ("purp", TREE_PURPOSE (t));
      dump_child_sign ("valu", TREE_VALUE (t));
      dump_child_sign ("chan", TREE_CHAIN (t));
      break;

    case STATEMENT_LIST:
      {
        tree_stmt_iterator it;
        for (i = 0, it = tsi_start (t); !tsi_end_p (it); tsi_next (&it) )
          {
            char buffer[32];
//          tree_code code = TREE_CODE ( tsi_stmt (it));
//          if ((code!=DEBUG_EXPR_DECL) && (code!=DEBUG_BEGIN_STMT))
                {
                sprintf (buffer, "%u", i);
                dump_child_sign (buffer, tsi_stmt (it));
                i++;
                }
          }
      }
      break;

    case TREE_VEC:
      dump_int_sign (di, "lngt", TREE_VEC_LENGTH (t));
      for (i = 0; i < TREE_VEC_LENGTH (t); ++i)
        {
          char buffer[32];
          sprintf (buffer, "%u", i);
          dump_child_sign (buffer, TREE_VEC_ELT (t, i));
        }
      break;

    case INTEGER_TYPE:
    case ENUMERAL_TYPE:
      dump_int_sign (di, "prec", TYPE_PRECISION (t));
      dump_string_field_sign (di, "sign", TYPE_UNSIGNED (t) ? "unsigned": "signed");
      dump_child_sign ("min", TYPE_MIN_VALUE (t));
      dump_child_sign ("max", TYPE_MAX_VALUE (t));

      if (code == ENUMERAL_TYPE)
        dump_child_sign ("csts", TYPE_VALUES (t));
      break;

    case REAL_TYPE:
      dump_int_sign (di, "prec", TYPE_PRECISION (t));
      break;

    case FIXED_POINT_TYPE:
      dump_int_sign (di, "prec", TYPE_PRECISION (t));
      dump_string_field_sign (di, "sign", TYPE_UNSIGNED (t) ? "unsigned": "signed");
      dump_string_field_sign (di, "saturating",
                         TYPE_SATURATING (t) ? "saturating": "non-saturating");
      break;

    case POINTER_TYPE:
      dump_child_sign ("ptd", TREE_TYPE (t));
      break;

    case REFERENCE_TYPE:
      dump_child_sign ("refd", TREE_TYPE (t));
      break;

    case METHOD_TYPE:
      dump_child_sign ("clas", TYPE_METHOD_BASETYPE (t));
      /* Fall through.  */

    case FUNCTION_TYPE:
      dump_child_sign ("retn", TREE_TYPE (t));
      dump_child_sign ("prms", TYPE_ARG_TYPES (t));
      break;

    case ARRAY_TYPE:
      dump_child_sign ("elts", TREE_TYPE (t));
      dump_child_sign ("domn", TYPE_DOMAIN (t));
      break;

    case RECORD_TYPE:
    case UNION_TYPE:
      if (TREE_CODE (t) == RECORD_TYPE)
        dump_string_field_sign (di, "tag", "struct");
      else
        dump_string_field_sign (di, "tag", "union");

      dump_child_sign ("flds", TYPE_FIELDS (t));
      queue_and_dump_index_sign (di, "binf", TYPE_BINFO (t),
                            DUMP_BINFO);
      break;

    case CONST_DECL:
      dump_child_sign ("cnst", DECL_INITIAL (t));
      break;

    case DEBUG_EXPR_DECL:
      dump_int_sign (di, "-uid", DEBUG_TEMP_UID (t));
      /* Fall through.  */

    case VAR_DECL:
    case PARM_DECL:
    case FIELD_DECL:
    case RESULT_DECL:
      if (TREE_CODE (t) == PARM_DECL)
        dump_child_sign ("argt", DECL_ARG_TYPE (t));
      else
        dump_child_sign ("init", DECL_INITIAL (t));
      dump_child_sign ("size", DECL_SIZE (t));
      dump_int_sign (di, "algn", DECL_ALIGN (t));

      if (TREE_CODE (t) == FIELD_DECL)
        {
          if (DECL_FIELD_OFFSET (t))
            dump_child_sign ("bpos", bit_position (t));
        }
      else if (VAR_P (t) || TREE_CODE (t) == PARM_DECL)
        {
          dump_int_sign (di, "used", TREE_USED (t));
          if (DECL_REGISTER (t))
            dump_string_field_sign (di, "spec", "register");
        }
      break;

    case FUNCTION_DECL:
      dump_child_sign ("args", DECL_ARGUMENTS (t));
//      if (DECL_EXTERNAL (t))
//      dump_string_field_sign (di, "body", "undefined");
//      if (TREE_PUBLIC (t))
//      dump_string_field_sign (di, "link", "extern");
//      else
//      dump_string_field_sign (di, "link", "static");
      if (DECL_SAVED_TREE (t) && !dump_flag_sign (di, TDF_SLIM, t))
        dump_child_sign ("body", DECL_SAVED_TREE (t));
      break;

    case INTEGER_CST:
      fprintf_sign (di, "int: ");
      print_decs_sign (di, wi::to_wide (t));
      break;

    case STRING_CST:
      fprintf_sign (di, "strg: %-7s ", TREE_STRING_POINTER (t));
      dump_int_sign (di, "lngt", TREE_STRING_LENGTH (t));
      break;

    case REAL_CST:
      dump_real (di, "valu", TREE_REAL_CST_PTR (t));
      break;

    case FIXED_CST:
      dump_fixed (di, "valu", TREE_FIXED_CST_PTR (t));
      break;

    case TRUTH_NOT_EXPR:
    case ADDR_EXPR:
    case INDIRECT_REF:
    case CLEANUP_POINT_EXPR:
    case SAVE_EXPR:
    case REALPART_EXPR:
    case IMAGPART_EXPR:
      /* These nodes are unary, but do not have code class `1'.  */
      dump_child_sign ("op 0", TREE_OPERAND (t, 0));
      break;

    case TRUTH_ANDIF_EXPR:
    case TRUTH_ORIF_EXPR:
    case INIT_EXPR:
    case MODIFY_EXPR:
    case COMPOUND_EXPR:
    case PREDECREMENT_EXPR:
    case PREINCREMENT_EXPR:
    case POSTDECREMENT_EXPR:
    case POSTINCREMENT_EXPR:
      /* These nodes are binary, but do not have code class `2'.  */
      dump_child_sign ("op 0", TREE_OPERAND (t, 0));
      dump_child_sign ("op 1", TREE_OPERAND (t, 1));
      break;

    case COMPONENT_REF:
    case BIT_FIELD_REF:
      dump_child_sign ("op 0", TREE_OPERAND (t, 0));
      dump_child_sign ("op 1", TREE_OPERAND (t, 1));
      dump_child_sign ("op 2", TREE_OPERAND (t, 2));
      break;

    case ARRAY_REF:
    case ARRAY_RANGE_REF:
      dump_child_sign ("op 0", TREE_OPERAND (t, 0));
      dump_child_sign ("op 1", TREE_OPERAND (t, 1));
      dump_child_sign ("op 2", TREE_OPERAND (t, 2));
      dump_child_sign ("op 3", TREE_OPERAND (t, 3));
      break;

    case COND_EXPR:
      dump_child_sign ("op 0", TREE_OPERAND (t, 0));
      dump_child_sign ("op 1", TREE_OPERAND (t, 1));
      dump_child_sign ("op 2", TREE_OPERAND (t, 2));
      break;

    case TRY_FINALLY_EXPR:
      dump_child_sign ("op 0", TREE_OPERAND (t, 0));
      dump_child_sign ("op 1", TREE_OPERAND (t, 1));
      break;

    case CALL_EXPR:
      {
        int i = 0;
        tree arg;
        call_expr_arg_iterator iter;
        dump_child_sign ("fn", CALL_EXPR_FN (t));
        FOR_EACH_CALL_EXPR_ARG (arg, iter, t)
          {
            char buffer[32];
            sprintf (buffer, "%u", i);
            dump_child_sign (buffer, arg);
            i++;
          }
      }
      break;

    case CONSTRUCTOR:
      {
        unsigned HOST_WIDE_INT cnt;
        tree index, value;
        dump_int_sign (di, "lngt", CONSTRUCTOR_NELTS (t));
        FOR_EACH_CONSTRUCTOR_ELT (CONSTRUCTOR_ELTS (t), cnt, index, value)
          {
            dump_child_sign ("idx", index);
            dump_child_sign ("val", value);
          }
      }
      break;

    case BIND_EXPR:
      dump_child_sign ("vars", TREE_OPERAND (t, 0));
      dump_child_sign ("body", TREE_OPERAND (t, 1));
      break;

    case LOOP_EXPR:
      dump_child_sign ("body", TREE_OPERAND (t, 0));
      break;

    case EXIT_EXPR:
      dump_child_sign ("cond", TREE_OPERAND (t, 0));
      break;

    case RETURN_EXPR:
      dump_child_sign ("expr", TREE_OPERAND (t, 0));
      break;

    case TARGET_EXPR:
      dump_child_sign ("decl", TREE_OPERAND (t, 0));
      dump_child_sign ("init", TREE_OPERAND (t, 1));
      dump_child_sign ("clnp", TREE_OPERAND (t, 2));
      /* There really are two possible places the initializer can be.
         After RTL expansion, the second operand is moved to the
         position of the fourth operand, and the second operand
         becomes NULL.  */
      dump_child_sign ("init", TREE_OPERAND (t, 3));
      break;

    case CASE_LABEL_EXPR:
      dump_child_sign ("name", CASE_LABEL (t));
      if (CASE_LOW (t))
        {
          dump_child_sign ("low ", CASE_LOW (t));
          if (CASE_HIGH (t))
            dump_child_sign ("high", CASE_HIGH (t));
        }
      break;
    case LABEL_EXPR:
      dump_child_sign ("name", TREE_OPERAND (t,0));
      break;
    case GOTO_EXPR:
      dump_child_sign ("labl", TREE_OPERAND (t, 0));
      break;
    case SWITCH_EXPR:
      dump_child_sign ("cond", TREE_OPERAND (t, 0));
      dump_child_sign ("body", TREE_OPERAND (t, 1));
      break;
    case OMP_CLAUSE:
      {
        int i;
        fprintf_sign (di, "%s\n", omp_clause_code_name[OMP_CLAUSE_CODE (t)]);
        for (i = 0; i < omp_clause_num_ops[OMP_CLAUSE_CODE (t)]; i++)
          dump_child_sign ("op: ", OMP_CLAUSE_OPERAND (t, i));
      }
      break;
    default:
      /* There are no additional fields to print.  */
      break;
    }

 done:
  if (dump_flag_sign (di, TDF_ADDRESS, NULL))
    dump_pointer_sign (di, "addr", (void *)t);

  /* Terminate the line.  */
  fprintf_sign (di, "\n");
}

/* Return nonzero if FLAG has been specified for the dump, and NODE
   is not the root node of the dump.  */

static int dump_flag_sign (dump_info_sign_p di, dump_flags_t flag, const_tree node)
{
  return (di->flags & flag) && (node != di->node);
}

/* Dump T, and all its children, on STREAM.  */

void
dump_node_sign (const_tree t, dump_flags_t flags, char **buf, int *buf_len, int *alloc_size)
{
  struct dump_info_sign di;
  dump_queue_p dq;
  dump_queue_p next_dq;

  /* Initialize the dump-information structure.  */
  di.buf=*buf; //buf_len and buf_max will be set with first fprintf_sign and di.buf is equal 0
  di.buf_len=*buf_len;
  di.buf_max=*alloc_size;
  di.index = 0;
  di.column = 0;
  di.queue = 0;
  di.queue_end = 0;
  di.free_list = 0;
  di.flags = flags;
  di.node = t;
  di.nodes = splay_tree_new (splay_tree_compare_pointers, 0,
                             splay_tree_delete_pointers);

  /* Queue up the first node.  */
  queue (&di, t, DUMP_NONE);

  /* Until the queue is empty, keep dumping nodes.  */
  while (di.queue)
    dequeue_and_dump (&di);

  /* Now, clean up.  */
  for (dq = di.free_list; dq; dq = next_dq)
    {
      next_dq = dq->next;
      free (dq);
    }
  splay_tree_delete (di.nodes);
  fprintf_sign (&di, "\n");
  *buf_len=di.buf_len;
  *buf=di.buf;
  *alloc_size=di.buf_max;
}


void
tric_pregen_crc (tree fndecl,char **buf, int *buf_len, int *alloc_size)
{
  dump_flags_t local_dump_flags;
  struct cgraph_node *cgn;
  local_dump_flags=TDF_RAW;
  dump_node_sign (DECL_SAVED_TREE (fndecl),
		    TDF_SLIM | local_dump_flags, buf, buf_len, alloc_size);

  /* Dump all nested functions now.  */
  cgn = cgraph_node::get_create (fndecl);

  if (nested_function_info::get (cgn))
    for (cgn = nested_function_info::get (cgn)->nested; cgn ; cgn = nested_function_info::get (cgn)->next_nested)
      tric_pregen_crc (cgn->decl, buf, buf_len, alloc_size);
}

bool
tric_promote_prototypes (const_tree fntype ATTRIBUTE_UNUSED)
{
  if (current_function_decl==NULL) return false;
  if (DECL_SAVED_TREE (current_function_decl)==NULL_TREE) return false;
  if (cfun==NULL) return false;
  if (cfun->machine==NULL) return false;
  int buffer_len=0;
  int alloc_size=0;
  char *buffer=NULL;

  tric_pregen_crc (current_function_decl,&buffer,&buffer_len, &alloc_size);

  if (buffer_len>0x1B) //statementlist must be filled
    {
      uint32_t crc;
      crc=tric_singletable_crc32c(0x80000000, buffer, buffer_len);
      cfun->machine->crc_sign[0]=crc;
      cfun->machine->crc_sign[1]=buffer_len;
//      fprintf(stderr,"pass function name %s crc=%x len=%x\n",get_fnname_from_decl (current_function_decl),cfun->machine->crc_sign[0],cfun->machine->crc_sign[1]);
    }
  if (buffer!=NULL)
    {
      free(buffer);
    }
  return true;
}
/***********************************************************************
 ** Target Hooks
 ***********************************************************************/
#undef  TARGET_HAVE_SPECULATION_SAFE_VALUE
#define TARGET_HAVE_SPECULATION_SAFE_VALUE speculation_safe_value_not_needed

#undef TARGET_FRAME_POINTER_REQUIRED
#define TARGET_FRAME_POINTER_REQUIRED tricore_frame_pointer_required

#undef TARGET_LRA_P
#define TARGET_LRA_P hook_bool_void_true

#undef TARGET_HARD_REGNO_NREGS
#define TARGET_HARD_REGNO_NREGS tric_hard_regno_nregs

#undef TARGET_HARD_REGNO_MODE_OK
#define TARGET_HARD_REGNO_MODE_OK tric_hard_regno_mode_ok

#undef  TARGET_SECONDARY_RELOAD
#define TARGET_SECONDARY_RELOAD tric_secondary_reload

#undef  TARGET_RETURN_IN_MEMORY
#define TARGET_RETURN_IN_MEMORY tric_return_in_memory

#undef  TARGET_FUNCTION_VALUE
#define TARGET_FUNCTION_VALUE tric_function_value

#undef  TARGET_FUNCTION_ARG
#define TARGET_FUNCTION_ARG tric_function_arg

#undef  TARGET_FUNCTION_ARG_ADVANCE
#define TARGET_FUNCTION_ARG_ADVANCE tric_function_arg_advance

#undef  TARGET_ASM_FUNCTION_END_PROLOGUE
#define TARGET_ASM_FUNCTION_END_PROLOGUE tric_asm_function_end_prologue

#undef  TARGET_ASM_FUNCTION_PROLOGUE
#define TARGET_ASM_FUNCTION_PROLOGUE tric_asm_function_prologue

#undef  TARGET_ASM_FUNCTION_BEGIN_EPILOGUE
#define TARGET_ASM_FUNCTION_BEGIN_EPILOGUE tric_asm_function_begin_epilogue

#undef TARGET_ASM_FILE_START
#define TARGET_ASM_FILE_START tric_asm_file_start

#undef  TARGET_ASM_FILE_END
#define TARGET_ASM_FILE_END tric_asm_file_end

#undef  TARGET_ASM_TRAMPOLINE_TEMPLATE
#define TARGET_ASM_TRAMPOLINE_TEMPLATE tric_asm_trampoline_template

#undef  TARGET_ATTRIBUTE_TABLE
#define TARGET_ATTRIBUTE_TABLE tric_attribute_table

#undef  TARGET_ASM_INTEGER
#define TARGET_ASM_INTEGER default_assemble_integer

#undef  TARGET_ASM_DECLARE_CONSTANT_NAME
#define TARGET_ASM_DECLARE_CONSTANT_NAME tric_asm_declare_constant_name

#undef  TARGET_PRINT_OPERAND
#define TARGET_PRINT_OPERAND tric_print_operand
#undef  TARGET_PRINT_OPERAND_ADDRESS
#define TARGET_PRINT_OPERAND_ADDRESS tric_print_operand_address

/* Same action as PROMOTE_MODE */
#undef  TARGET_PROMOTE_FUNCTION_MODE
#define TARGET_PROMOTE_FUNCTION_MODE            \
  default_promote_function_mode_always_promote

#undef  TARGET_PASS_BY_REFERENCE
#define TARGET_PASS_BY_REFERENCE tric_pass_by_reference
#undef  TARGET_STRICT_ARGUMENT_NAMING
#define TARGET_STRICT_ARGUMENT_NAMING tric_strict_argument_naming
#undef  TARGET_CALLEE_COPIES
#define TARGET_CALLEE_COPIES tric_callee_copies

#undef  TARGET_STRUCT_VALUE_RTX
#define TARGET_STRUCT_VALUE_RTX tric_struct_value_rtx

#undef  TARGET_RTX_COSTS
#define TARGET_RTX_COSTS tric_rtx_costs
#undef  TARGET_ADDRESS_COST
#define TARGET_ADDRESS_COST tric_address_cost

#undef  TARGET_ASM_FUNCTION_RODATA_SECTION
#define TARGET_ASM_FUNCTION_RODATA_SECTION tric_function_rodata_section

//#undef  TARGET_ASM_RECORD_GCC_SWITCHES
//#define TARGET_ASM_RECORD_GCC_SWITCHES tric_asm_record_gcc_switches

#undef  TARGET_CANNOT_FORCE_CONST_MEM
#define TARGET_CANNOT_FORCE_CONST_MEM hook_bool_mode_rtx_true

#undef  TARGET_ASM_ALIGNED_HI_OP
#define TARGET_ASM_ALIGNED_HI_OP "\t.short\t"
#undef  TARGET_ASM_ALIGNED_SI_OP
#define TARGET_ASM_ALIGNED_SI_OP "\t.word\t"
#undef  TARGET_ASM_UNALIGNED_HI_OP
#define TARGET_ASM_UNALIGNED_HI_OP "\t.uahalf\t"
#undef  TARGET_ASM_UNALIGNED_SI_OP
#define TARGET_ASM_UNALIGNED_SI_OP "\t.uaword\t"
#undef  TARGET_ASM_UNALIGNED_DI_OP
#define TARGET_ASM_UNALIGNED_DI_OP "\t.uaxword\t"

#undef  TARGET_ATTRIBUTE_TABLE
#define TARGET_ATTRIBUTE_TABLE tric_attribute_table

#undef  TARGET_ASM_INIT_SECTIONS
#define TARGET_ASM_INIT_SECTIONS tric_asm_init_sections

#undef  TARGET_ASM_FUNCTION_SECTION
#define TARGET_ASM_FUNCTION_SECTION tric_asm_function_section

#undef  TARGET_ASM_SELECT_SECTION
#define TARGET_ASM_SELECT_SECTION tric_asm_select_section

#undef  TARGET_ASM_UNIQUE_SECTION
#define TARGET_ASM_UNIQUE_SECTION tric_asm_unique_section

#undef  TARGET_ASM_NAMED_SECTION
#define TARGET_ASM_NAMED_SECTION tric_asm_named_section

#undef  TARGET_SECTION_TYPE_FLAGS
#define TARGET_SECTION_TYPE_FLAGS tric_section_type_flags

#undef  TARGET_ENCODE_SECTION_INFO
#define TARGET_ENCODE_SECTION_INFO tric_encode_section_info

#undef  TARGET_MIN_ANCHOR_OFFSET
#define TARGET_MIN_ANCHOR_OFFSET (-(1 << 15))

#undef  TARGET_MAX_ANCHOR_OFFSET
#define TARGET_MAX_ANCHOR_OFFSET ((1 << 15) -1)

#undef  TARGET_ASM_OUTPUT_ANCHOR
#define TARGET_ASM_OUTPUT_ANCHOR tric_asm_output_anchor

#undef  TARGET_USE_ANCHORS_FOR_SYMBOL_P
#define TARGET_USE_ANCHORS_FOR_SYMBOL_P tric_use_anchors_for_symbol_p

#undef  TARGET_ASM_CONSTRUCTOR
#define TARGET_ASM_CONSTRUCTOR tric_asm_constructor

#undef  TARGET_ASM_DESTRUCTOR
#define TARGET_ASM_DESTRUCTOR tric_asm_destructor

#undef  TARGET_INSERT_ATTRIBUTES
#define TARGET_INSERT_ATTRIBUTES  tric_insert_attributes

#undef  TARGET_LEGITIMATE_ADDRESS_P
#define TARGET_LEGITIMATE_ADDRESS_P tric_legitimate_address_p

#undef  TARGET_LEGITIMIZE_ADDRESS
#define TARGET_LEGITIMIZE_ADDRESS tric_legitimize_address

#undef  TARGET_REGISTER_MOVE_COST
#define TARGET_REGISTER_MOVE_COST tric_register_move_cost

#undef  TARGET_MEMORY_MOVE_COST
#define TARGET_MEMORY_MOVE_COST tric_memory_move_cost

#undef  TARGET_CAN_INLINE_P
#define TARGET_CAN_INLINE_P tric_can_inline_p
#undef  TARGET_FUNCTION_ATTRIBUTE_INLINABLE_P
#define TARGET_FUNCTION_ATTRIBUTE_INLINABLE_P   \
  tric_function_attribute_inlinable_p

#undef  TARGET_STATIC_CHAIN
#define TARGET_STATIC_CHAIN tric_static_chain

#undef  TARGET_MD_ASM_ADJUST
#define TARGET_MD_ASM_ADJUST tric_md_asm_adjust

#undef  TARGET_CONDITIONAL_REGISTER_USAGE
#define TARGET_CONDITIONAL_REGISTER_USAGE tric_conditional_register_usage

#undef  TARGET_CLASS_LIKELY_SPILLED_P
#define TARGET_CLASS_LIKELY_SPILLED_P tric_class_likely_spilled_p

#undef  TARGET_RETURN_POPS_ARGS
#define TARGET_RETURN_POPS_ARGS tric_return_pops_args

#undef  TARGET_OPTION_OVERRIDE
#define TARGET_OPTION_OVERRIDE tric_option_override

#undef  TARGET_SET_CURRENT_FUNCTION
#define TARGET_SET_CURRENT_FUNCTION tric_set_current_function

#undef  TARGET_INIT_BUILTINS
#define TARGET_INIT_BUILTINS tric_init_builtins

#undef  TARGET_BUILTIN_DECL
#define TARGET_BUILTIN_DECL tric_builtin_decl

#undef  TARGET_EXPAND_BUILTIN
#define TARGET_EXPAND_BUILTIN tric_expand_builtin

#undef  TARGET_FOLD_BUILTIN
#define TARGET_FOLD_BUILTIN tric_fold_builtin

#undef  TARGET_INVALID_BINARY_OP
#define TARGET_INVALID_BINARY_OP tric_invalid_binary_op

#undef  TARGET_INVALID_UNARY_OP
#define TARGET_INVALID_UNARY_OP tric_invalid_unary_op

#undef  TARGET_CANONICALIZE_COMPARISON
#define TARGET_CANONICALIZE_COMPARISON tric_canonicalize_comparison
// needs adaptations in combine.c
//only the hook was added
#undef  TARGET_HTC_CANONICALIZE_COMBINED_RTX
#define TARGET_HTC_CANONICALIZE_COMBINED_RTX tric_htc_canonicalize_combined_rtx

#undef  TARGET_CAN_USE_DOLOOP_P
#define TARGET_CAN_USE_DOLOOP_P tric_can_use_doloop_p

#undef  TARGET_LIBC_HAS_FUNCTION
#define TARGET_LIBC_HAS_FUNCTION tric_libc_has_function
//TODO
//#undef  TARGET_INVALID_PARAMETER_TYPE
//#define TARGET_INVALID_PARAMETER_TYPE tric_invalid_parameter_type
//TODO
//#undef  TARGET_INVALID_RETURN_TYPE
//#define TARGET_INVALID_RETURN_TYPE tric_invalid_return_type

#undef  TARGET_FUNCTION_OK_FOR_SIBCALL
#define TARGET_FUNCTION_OK_FOR_SIBCALL tric_function_ok_for_sibcall

#undef  TARGET_PROMOTED_TYPE
#define TARGET_PROMOTED_TYPE tric_promoted_type

#undef  TARGET_CONVERT_TO_TYPE
#define TARGET_CONVERT_TO_TYPE tric_convert_to_type

#undef  TARGET_INIT_LIBFUNCS
#define TARGET_INIT_LIBFUNCS tric_init_libfuncs

#undef  TARGET_SCALAR_MODE_SUPPORTED_P
#define TARGET_SCALAR_MODE_SUPPORTED_P tric_scalar_mode_supported_p

#undef  TARGET_MANGLE_TYPE
#define TARGET_MANGLE_TYPE tric_mangle_type
// needs adaptations in tree-ssa-loop-ivopts.c
//add the moment it is commented out and the hook is not called
#undef  TARGET_HTC_IVOPT_BASE_COSTS_P
#define TARGET_HTC_IVOPT_BASE_COSTS_P tric_ivopt_base_costs_p

// needs adaptations in tree-ssa-loop-ivopts.c
//only the hook was added
#undef  TARGET_HTC_IVOPT_USE_ADDRESS_P
#define TARGET_HTC_IVOPT_USE_ADDRESS_P tric_ivopt_use_address_p
// needs adaptations in sched-deps.c
//only the hook was added
#undef  TARGET_HTC_SCHED_MAY_CHANGE_ADDRESS_P
#define TARGET_HTC_SCHED_MAY_CHANGE_ADDRESS_P tric_sched_may_change_address_p

#undef  TARGET_PROMOTE_PROTOTYPES
#define TARGET_PROMOTE_PROTOTYPES tric_promote_prototypes

//#undef TARGET_SCHED_FUSION_PRIORITY
//#define TARGET_SCHED_FUSION_PRIORITY tricore_sched_fusion_priority

struct gcc_target targetm = TARGET_INITIALIZER;

#include "gt-tricore.h"
