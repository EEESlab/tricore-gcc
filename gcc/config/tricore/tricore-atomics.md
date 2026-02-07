;; DSYNC — Data Synchronize.
;; Acts as a full memory barrier: it enforces ordering of memory accesses and
(define_insn "tricore_dsync"
  [(unspec_volatile [(const_int 0)] UNSPECV_DSYNC)]
  ""
  "dsync"
)

;; Atomic load (SImode)
(define_expand "atomic_loadsi"
  [(set (match_operand:SI 0 "register_operand" "")
        (match_operand:SI 1 "memory_operand" ""))
   (match_operand:SI 2 "const_int_operand" "")]
  ""
{
  enum memmodel model = (enum memmodel) INTVAL (operands[2]);

  /* Emit the basic load first.  */
  emit_move_insn (operands[0], operands[1]);

  /* Add fences according to memory order.  */
  if (model != MEMMODEL_RELAXED)
    {
      emit_insn (gen_tricore_dsync ());
    }

  DONE;
})

;; Atomic load (SImode)
(define_expand "atomic_storesi"
  [(set (match_operand:SI 0 "memory_operand" "")
        (match_operand:SI 1 "register_operand" ""))
   (match_operand:SI 2 "const_int_operand" "")]
  ""
{
  enum memmodel model = (enum memmodel) INTVAL (operands[2]);

  /* Add fences according to memory order.  */
  if (model != MEMMODEL_RELAXED)
    {
      emit_insn (gen_tricore_dsync ());
    }

  /* Emit the basic store.  */
  emit_move_insn (operands[0], operands[1]);

  DONE;
})

;; Atomic exchange (SI mode)
;; result = atomic_exchange_explicit(*mem, val, memmodel)
;; operands:
;;   0: result register (old value on return)
;;   1: memory (vok_memory_operand)
;;   2: new value (register)
;;   3: memmodel (const_int, enum memmodel)

(define_expand "atomic_exchangesi"
  [(match_operand:SI 0 "register_operand" "")
   (match_operand:SI 1 "vok_memory_operand" "")
   (match_operand:SI 2 "register_operand" "")
   (match_operand:SI 3 "const_int_operand" "")]
  ""
{
  enum memmodel model = (enum memmodel) INTVAL (operands[3]);
  bool need_before = false;
  bool need_after  = false;

  /* Decide where to insert dsync based on memory order.  */
  switch (model)
    {
    case MEMMODEL_RELAXED:
      /* No fences.  */
      break;

    case MEMMODEL_CONSUME:
    case MEMMODEL_ACQUIRE:
      /* Ensure later accesses don't move before the RMW.  */
      need_after = true;
      break;

    case MEMMODEL_RELEASE:
      /* Ensure earlier accesses don't move after the RMW.  */
      need_before = true;
      break;

    case MEMMODEL_ACQ_REL:
      need_before = true;
      need_after  = true;
      break;

    case MEMMODEL_SEQ_CST:
    default:
      /* Safest: treat as acq_rel / seq_cst.  */
      need_before = true;
      need_after  = true;
      break;
    }

  if (need_before)
    emit_insn (gen_tricore_dsync ());

  /* swap_w_insn expects operand 0 to contain the NEW value on entry,
     and returns the OLD value in that same register.
   */
  if (!rtx_equal_p (operands[0], operands[2]))
    emit_move_insn (operands[0], operands[2]);

  emit_insn (gen_swap_w_insn (operands[0], operands[1], operands[0]));

  if (need_after)
    emit_insn (gen_tricore_dsync ());

  DONE;
})

;; Atomic compare-and-swap (SI mode)
;;   bool success = __atomic_compare_exchange_n (mem, &expected, desired,
;;                                               weak, success_mm, failure_mm);
;; operands:
;;   0: bool result (QImode register – GCC will accept SImode too, but QI is common)
;;   1: old value output register (same mode as mem, here SImode)
;;   2: memory (vok_memory_operand)
;;   3: expected-in register (original expected value)
;;   4: desired value register
;;   5: const_int is_weak  (0 = strong, 1 = weak)   [we ignore, always strong]
;;   6: const_int success_memmodel
;;   7: const_int failure_memmodel
(define_expand "atomic_compare_and_swapsi"
  [(match_operand:QI 0 "register_operand" "")       ; success flag
   (match_operand:SI 1 "register_operand" "")       ; old value out
   (match_operand:SI 2 "memory_operand" "")         ; *mem
   (match_operand:SI 3 "register_operand" "")       ; expected
   (match_operand:SI 4 "register_operand" "")       ; desired
   (match_operand:SI 5 "const_int_operand" "")      ; is_weak (ignored)
   (match_operand:SI 6 "const_int_operand" "")      ; success memmodel
   (match_operand:SI 7 "const_int_operand" "")]     ; failure memmodel
  "TRIC_HAVE_CMPSWAP_W"
{
  enum memmodel model_s = (enum memmodel) INTVAL (operands[6]);
  enum memmodel model_f = (enum memmodel) INTVAL (operands[7]);
  enum memmodel model =
    (model_s > model_f ? model_s : model_f);

  bool need_before = false;
  bool need_after  = false;

  switch (model)
    {
    case MEMMODEL_RELAXED:
      break;

    case MEMMODEL_CONSUME:
    case MEMMODEL_ACQUIRE:
      need_after = true;
      break;

    case MEMMODEL_RELEASE:
      need_before = true;
      break;

    case MEMMODEL_ACQ_REL:
      need_before = true;
      need_after  = true;
      break;

    case MEMMODEL_SEQ_CST:
    default:
      need_before = true;
      need_after  = true;
      break;
    }

  if (need_before)
    emit_insn (gen_tricore_dsync ());

  /* Keep original expected for success test.  */
  rtx expected_orig = gen_reg_rtx (SImode);
  emit_move_insn (expected_orig, operands[3]);

  /* Extract address from memory operand and put it in a register.
     TriCore is 32-bit so Pmode == SImode.  */
  rtx addr = XEXP (operands[2], 0);
  addr = force_reg (Pmode, addr);

  /* Call the helper expander:
       cmpswap_w (old, addr, desired, expected)
     It wraps addr in MEM and builds the DI pair internally.  */
  emit_insn (gen_cmpswap_w (operands[1], addr, operands[4], operands[3]));

  if (need_after)
    emit_insn (gen_tricore_dsync ());

  /* success = (old == expected_orig);  */
  rtx cmp = gen_rtx_EQ (SImode, operands[1], expected_orig);
  rtx tmp = gen_reg_rtx (SImode);

  emit_insn (gen_rtx_SET (tmp, cmp));
  emit_insn (gen_rtx_SET (operands[0],
                          gen_rtx_SUBREG (QImode, tmp, 0)));

  DONE;
})

;; -------------------------------------------------------------------
;; Atomic RMW operators
;; -------------------------------------------------------------------


;; -------------------------------------------------------------------
;; atomic_fetch_OPsi:
;;   old = atomic_fetch_<op>_explicit (*mem, val, memmodel)
;;   Operations: add, sub, or, xor
;; -------------------------------------------------------------------

(define_expand "atomic_fetch_<atomic_op_name>si"
  [(match_operand:SI 0 "register_operand" "")        ; result (old)
   (match_operand:SI 1 "memory_operand"   "")        ; *mem
   (match_operand:SI 2 "register_operand" "")        ; val
   (match_operand:SI 3 "const_int_operand" "")       ; memmodel

   (set (match_dup 0)
        (atomic_op:SI (match_dup 0) (match_dup 2)))]
  "TRIC_HAVE_CMPSWAP_W"
{
  enum memmodel model = (enum memmodel) INTVAL (operands[3]);

  rtx mem      = operands[1];
  rtx val      = operands[2];

  rtx old      = gen_reg_rtx (SImode);
  rtx newv     = gen_reg_rtx (SImode);
  rtx expected = gen_reg_rtx (SImode);
  rtx success  = gen_reg_rtx (QImode);

  rtx model_rtx = GEN_INT (model);

  rtx loop_label = gen_label_rtx ();

  emit_label (loop_label);

  /* old = *mem;  (plain load; ordering comes from CAS) */
  emit_move_insn (old, mem);

  /* newv = old OP val; */
  emit_insn (gen_<atomic_op_name>si3 (newv, old, val));

  /* expected = old;  */
  emit_move_insn (expected, old);

  /* success, old, mem, expected, newv, is_weak=0, model, model */
  emit_insn (gen_atomic_compare_and_swapsi (success,
                                            old,
                                            mem,
                                            expected,
                                            newv,
                                            const0_rtx,   /* is_weak = false */
                                            model_rtx,    /* success MO  */
                                            model_rtx));  /* failure MO */

  /* if (!success) goto loop_label; */
  emit_cmp_and_jump_insns (success, const0_rtx,
                           EQ, NULL_RTX, QImode, 1, loop_label);

  /* fetch_OP returns the *old* value. */
  emit_move_insn (operands[0], old);

  DONE;
})

;; -------------------------------------------------------------------
;; atomic_OP_fetchsi:
;;   new = atomic_<op>_fetch_explicit (*mem, val, memmodel)
;;   Operations: add, sub, and, or, xor
;; -------------------------------------------------------------------

(define_expand "atomic_<atomic_op_name>_fetchsi"
  [(match_operand:SI 0 "register_operand" "")        ; result (new)
   (match_operand:SI 1 "memory_operand"   "")        ; *mem
   (match_operand:SI 2 "register_operand" "")        ; val
   (match_operand:SI 3 "const_int_operand" "")       ; memmodel

   (set (match_dup 0)
        (atomic_op:SI (match_dup 0) (match_dup 2)))]
  "TRIC_HAVE_CMPSWAP_W"
{
  enum memmodel model = (enum memmodel) INTVAL (operands[3]);

  rtx mem      = operands[1];
  rtx val      = operands[2];

  rtx old      = gen_reg_rtx (SImode);
  rtx newv     = gen_reg_rtx (SImode);
  rtx expected = gen_reg_rtx (SImode);
  rtx success  = gen_reg_rtx (QImode);

  rtx model_rtx = GEN_INT (model);

  rtx loop_label = gen_label_rtx ();

  emit_label (loop_label);

  emit_move_insn (old, mem);                      /* old = *mem; */
  emit_insn (gen_<atomic_op_name>si3 (newv, old, val));
  emit_move_insn (expected, old);

  emit_insn (gen_atomic_compare_and_swapsi (success,
                                            old,
                                            mem,
                                            expected,
                                            newv,
                                            const0_rtx,
                                            model_rtx,
                                            model_rtx));

  emit_cmp_and_jump_insns (success, const0_rtx,
                            EQ, NULL_RTX, QImode, 1, loop_label);

  /* _OP_fetch returns the *new* value. */
  emit_move_insn (operands[0], newv);

  DONE;
})

;; -------------------------------------------------------------------
;; atomic_test_and_set:
;;   bool old = atomic_test_and_set (flag, memmodel);
;;
;; Implements:
;;   do {
;;     old = *mem;
;;   } while (!CAS(mem, expected=old, desired=1));
;;   return old != 0;
;;
;; Uses SImode CAS (atomic_compare_and_swapsi) on the word at &flag.
;; -------------------------------------------------------------------

(define_expand "atomic_test_and_set"
  [(match_operand:QI 0 "register_operand" "")        ; result (QImode boolean)
   (match_operand:QI 1 "memory_operand"   "")        ; *flag (byte)
   (match_operand:SI 2 "const_int_operand" "")]      ; memmodel
  "TRIC_HAVE_CMPSWAP_W"
{
  enum memmodel model = (enum memmodel) INTVAL (operands[2]);

  /* Original QImode memory.  */
  rtx mem_qi = operands[1];

  /* Use a 32-bit view for the CAS.  */
  rtx addr   = XEXP (mem_qi, 0);                     /* address of flag      */
  rtx mem_si = gen_rtx_MEM (SImode, addr);           /* word at same address */
  MEM_VOLATILE_P (mem_si) = 1;

  rtx old      = gen_reg_rtx (SImode);
  rtx newv     = GEN_INT (1);                        /* desired = 1 (set)    */
  rtx expected = gen_reg_rtx (SImode);
  rtx success  = gen_reg_rtx (QImode);

  rtx model_rtx = GEN_INT (model);
  rtx loop_label = gen_label_rtx ();

  emit_label (loop_label);

  /* old = *mem_si;  */
  emit_move_insn (old, mem_si);

  /* expected = old; */
  emit_move_insn (expected, old);

  /* success, old, mem_si, expected, newv, is_weak=0, model, model */
  emit_insn (gen_atomic_compare_and_swapsi (success,
                                            old,
                                            mem_si,
                                            expected,
                                            newv,
                                            const0_rtx,   /* is_weak = false */
                                            model_rtx,    /* success MO  */
                                            model_rtx));  /* failure MO */

  /* if (!success) goto loop_label; */
  emit_cmp_and_jump_insns (success, const0_rtx,
                           EQ, NULL_RTX, QImode, 1, loop_label);

  /* Result: old != 0, in QImode. */
  rtx cmp = gen_rtx_NE (SImode, old, const0_rtx);
  rtx tmp = gen_reg_rtx (SImode);

  emit_insn (gen_rtx_SET (tmp, cmp));
  emit_insn (gen_rtx_SET (operands[0],
                          gen_rtx_SUBREG (QImode, tmp, 0)));

  DONE;
})

;; -------------------------------------------------------------------
;; atomic_thread_fence(memmodel)
;;
;; Operand:
;;   0: const_int memmodel (enum memmodel)
;; -------------------------------------------------------------------

(define_expand "atomic_thread_fence"
  [(match_operand:SI 0 "const_int_operand" "")]
  ""
{
  enum memmodel model = (enum memmodel) INTVAL (operands[0]);

  switch (model)
    {
    case MEMMODEL_RELAXED:
      /* No fence needed.  */
      break;

    case MEMMODEL_CONSUME:
    case MEMMODEL_ACQUIRE:
    case MEMMODEL_RELEASE:
    case MEMMODEL_ACQ_REL:
    case MEMMODEL_SEQ_CST:
    default:
      /* Strong but legal: use a full data barrier for all non-relaxed orders.  */
      emit_insn (gen_tricore_dsync ());
      break;
    }

  DONE;
})

;; -------------------------------------------------------------------
;; atomic_signal_fence(memmodel)
;;
;; Operand:
;;   0: const_int memmodel (enum memmodel)
;; -------------------------------------------------------------------

(define_expand "atomic_signal_fence"
  [(match_operand:SI 0 "const_int_operand" "")]
  ""
{
  enum memmodel model = (enum memmodel) INTVAL (operands[0]);

  switch (model)
    {
    case MEMMODEL_RELAXED:
      /* No barrier needed.  */
      break;

    case MEMMODEL_CONSUME:
    case MEMMODEL_ACQUIRE:
    case MEMMODEL_RELEASE:
    case MEMMODEL_ACQ_REL:
    case MEMMODEL_SEQ_CST:
    default:
      /* Compiler/scheduling barrier only.  */
      emit_insn (gen_nopv ());
      break;
    }

  DONE;
})

