///
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_MyMultiSearcher_H
#define S2E_PLUGINS_MyMultiSearcher_H

#include <deque>
#include <inttypes.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/uEmu/ARMFunctionMonitor.h>
#include <s2e/Plugins/uEmu/InvalidStatesDetection.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/SymbolicHardwareHook.h>
#include <vector>

#include <llvm/ADT/SmallVector.h>

namespace s2e {
namespace plugins {
enum PeripheralRegisterType { TIRQS, TIRQC, T0, T1, PT1, T2, T3 }; // IRQ Type only used in KB
enum KBUpdateReason { Valid, Invlid };
namespace hw {
typedef std::vector<uint8_t> ConcreteArray;
typedef std::pair<uint64_t, uint64_t> SymbolicMmioRange;
typedef llvm::SmallVector<SymbolicMmioRange, 4> SymbolicMmioRanges;
typedef std::pair<uint32_t /* peripheraladdress */, uint32_t /* pc */> UniquePeripheral;
typedef std::map<uint32_t /* peripheraladdress */, uint32_t /* kind of type */> TypeFlagPeripheralMap;
typedef std::map<uint32_t /* peripheraladdress */, uint32_t /* size */> UniquePeripheralSizeMap;
typedef std::map<uint32_t /* peripheraladdress */, uint32_t /* last write value */> WritePeripheralMap;
typedef std::map<uint64_t /* caller pc&function regs hash value*/, uint32_t /* value */> CWMap;
typedef std::pair<uint64_t /* unique no */, uint32_t /* value */> NumPair;

typedef std::map<uint32_t /* peripheraladdress */,
                 std::map<uint32_t /* pc */, std::pair<uint64_t /* caller pc&function regs hash value */, NumPair>>>
    T0PeripheralMap;
typedef std::map<UniquePeripheral, uint32_t /* value */> T1PeripheralMap;
typedef std::map<UniquePeripheral, std::pair<uint64_t /* caller pc&function regs hash value */, uint32_t /* value */>>
    T1BPeripheralMap;
typedef std::map<UniquePeripheral, std::pair<uint64_t /* caller pc&function regs hash value */, NumPair>>
    T1BNPeripheralMap;
typedef std::map<UniquePeripheral, CWMap> T2PeripheralMap;
typedef std::map<UniquePeripheral, uint32_t /* last fork count */> PeripheralForkCount;

typedef std::map<uint32_t /* phaddr */, uint32_t /* value */> PeripheralMap;
typedef std::map<uint32_t /* CR phaddr */, std::map<uint32_t /* CR value */, std::deque<uint32_t>>> IRQCRMap;
typedef std::map<UniquePeripheral, uint32_t /* irq_no */> IRQSRMap;
typedef std::pair<uint32_t /* IRQ No */, uint32_t /* phaddr */> IRQPhPair;
typedef std::map<IRQPhPair /* phaddr */, uint32_t /* flag */> TIRQPeripheralMapFlag;
typedef std::map<IRQPhPair /* phaddr */, IRQCRMap> TIRQCPeripheralMap;
typedef std::tuple<uint32_t, /* irq no */ uint32_t /* phaddr */, uint32_t /* pc */> IRQPhTuple;
typedef std::map<IRQPhTuple /* phaddr */, uint32_t /* flag */> TIRQSPeripheralMapFlag;
typedef std::map<IRQPhTuple, std::deque<uint32_t>> TIRQSPeripheralMap;
typedef std::map<uint32_t /* phaddr */, std::deque<uint32_t>> T3PeripheralMap;
typedef std::map<uint64_t /* unique no */, uint32_t /* value */> NumMap;
typedef std::map<uint64_t /* caller pc&function regs hash value */, NumPair> CWNOMap;
typedef std::map<UniquePeripheral, CWNOMap> AllKnowledgeBaseMap;
typedef std::map<uint32_t /* phaddr */, NumMap> AllKnowledgeBaseNoMap;

typedef std::map<uint32_t /* peripheraladdress */, std::pair<uint32_t /* size */, uint32_t /* count */>>
    ReadPeripheralMap;
typedef std::pair<uint32_t /* peripheraladdress */, std::pair<uint32_t /* size */, uint32_t /* count */>> ReadTUPLE;
typedef std::tuple<uint32_t /* phaddr */, uint32_t /* pc */, uint64_t /* caller pc&function regs hash value */> T2Tuple;
typedef std::vector<std::vector<S2EExecutionState *>> ForkStateStack;

class MyMultiSearcher : public Plugin {
    S2E_PLUGIN

private:
    klee::Searcher *m_top;
    SymbolicMmioRanges m_mmio;
    sigc::connection onStateKillConnection;
    sigc::connection onStateForkConnection;
    sigc::connection onStateForkDecideConnection;
    sigc::connection onStateSwitchConnection;
    sigc::connection onSymbolicAddressConnection;
    sigc::connection onInterruptExitonnection;
    InvalidStatesDetection *onInvalidStateDectionConnection;
    ARMFunctionMonitor *onARMFunctionConnection;
    std::map<uint32_t ,std::vector<uint32_t>> my_stateClasses;
    // dynamic analysis mode
    T1BPeripheralMap cache_t1_type_phs;
    T1BPeripheralMap cache_pt1_type_phs;
    T1PeripheralMap cache_t1_type_flag_phs; // 1: indicates t1 2: indicates pt1
    T1PeripheralMap cache_t2_type_flag_phs;
    T2PeripheralMap cache_t2_type_phs;
    T3PeripheralMap cache_t3_type_phs_backup;
    T3PeripheralMap cache_t3_type_phs;
    TypeFlagPeripheralMap cache_t3_io_type_phs;
    TIRQCPeripheralMap cache_tirqc_type_phs;
    TIRQSPeripheralMap cache_tirqs_type_phs;
    TIRQPeripheralMapFlag cache_type_irqc_flag;
    TIRQSPeripheralMapFlag cache_type_irqs_flag;
    TypeFlagPeripheralMap cache_type_flag_phs;
    UniquePeripheralSizeMap cache_dr_type_size;
    //  knowledge extraction mode
    std::map<uint32_t /* pc */, uint32_t /* count */> alive_points_count;
    TypeFlagPeripheralMap
        irq_data_phs; // 2: donates data reg in interrupt which should not meet conditions in irq handle. 1 and 3 cannot be data reg.
    AllKnowledgeBaseNoMap cache_all_cache_phs;
    IRQSRMap possible_irq_srs;
    TIRQSPeripheralMap possible_irq_values;
    TIRQSPeripheralMap impossible_irq_values;
    TIRQSPeripheralMap already_used_irq_values;

    std::map<uint64_t /* path num */, uint32_t /* flag */> all_path_map;
    std::map<uint64_t /* path num */, uint32_t /* flag */> all_searched_path_map;
    std::map<T2Tuple, std::vector<uint32_t> /* unique value */> all_fork_states_value_map;
    TypeFlagPeripheralMap PT1_phs;
    TypeFlagPeripheralMap mulit_value_dr;
    TypeFlagPeripheralMap fixed_type_irq_flag;

    std::map<uint32_t /*irq no*/, PeripheralMap> irq_crs;
    std::map<uint32_t /*irq no*/, std::deque<uint32_t>> irq_srs;
    uint32_t t2_max_context;
    uint32_t t3_max_symbolic_count;
    bool auto_mode_switch;

    uint32_t round_count;    // learning count
    bool no_new_branch_flag; // use to judge whether new states has been forked casued by possiable status phs
    bool irq_no_new_branch_flag;
    std::vector<S2EExecutionState *> irq_states;           // forking states in interrupt
    std::vector<S2EExecutionState *> false_irq_states;     // forking states in interrupt
    std::vector<S2EExecutionState *> learning_mode_states; // forking states in interrupt
    ForkStateStack unsearched_condition_fork_states;       // all forking states
    int fs;                                                // count for false status fork states kill;
    std::vector<S2EExecutionState *> false_type_phs_fork_states;
    std::map<uint32_t, uint32_t> symbolic_address_count; // record symbolic address

    std::string fileName;
    std::string firmwareName;
    
    bool enable_fuzzing;
   
    std::vector<uint32_t> valid_phs;
    bool ConcreteT3Regs(S2EExecutionState *state);
 
    bool getPeripheralExecutionState(std::string variablePeripheralName, uint32_t *phaddr, uint32_t *pc,
                                     uint64_t *regs_hash, uint64_t *no);

public:
    sigc::signal<void, S2EExecutionState *, PeripheralRegisterType /* type */, uint64_t /* physicalAddress */,
                 uint32_t /* t3 rest count */, uint32_t * /* size */, uint32_t * /* fuzz input */,
                 bool * /* enable fuzz */>
        onFuzzingInput;

    sigc::signal<void, S2EExecutionState *, bool /* fuzzing to learning mode */> onModeSwitch;

    sigc::signal<void, S2EExecutionState *, uint64_t /* phaddr */> onInvalidPHs;

    MyMultiSearcher(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();
    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);
    void switchModefromLtoF(S2EExecutionState *state);
    void updateState(S2EExecutionState *state);
    void onARMFunctionReturn(S2EExecutionState *state, uint32_t return_pc);
    void onARMFunctionCall(S2EExecutionState *state, uint32_t caller_pc, uint64_t function_hash);
    void onInvalidStatesDetection(S2EExecutionState *state, uint32_t pc, InvalidStatesType type, uint64_t tb_num);
    void onLearningTerminationDetection(S2EExecutionState *state, bool *actual_end,
                                                             uint64_t tb_num)
};

} // namespace hw
} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MyMultiSearcher_H
