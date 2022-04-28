///
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <boost/regex.hpp>
#include <klee/util/ExprUtil.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include "MyMultiSearcher.h"

#include <llvm/Support/CommandLine.h>

using namespace klee;

namespace {
llvm::cl::opt<bool> DebugSymbHw("debug-symbolic-hardware", llvm::cl::init(true));
}

namespace s2e {
namespace plugins {
namespace hw {




static const boost::regex KBGeneralPeripheralRegEx("(.+)_(.+)_(.+)_(.+)_(.+)", boost::regex::perl);
static const boost::regex KBIRQPeripheralRegEx("(.+)_(.+)_(.+)_(.+)_(.+)_(.+)", boost::regex::perl);
static const boost::regex KBDRPeripheralRegEx("(.+)_(.+)_(.+)_(.+)", boost::regex::perl);
static const boost::regex MyMultiSearcherRegEx("v\\d+_iommuread_(.+)_(.+)_(.+)", boost::regex::perl);

S2E_DEFINE_PLUGIN(MyMultiSearcher, "MyMultiSearcher S2E plugin", "MyMultiSearcher",
                  "InvalidStatesDetection", "ARMFunctionMonitor");

namespace {
class MyMultiSearcherState : public PluginState {
private:
    AllKnowledgeBaseMap lastforkphs;
    std::pair<uint32_t, std::vector<uint32_t>> last_fork_cond;
    std::map<uint32_t /* irq num */, AllKnowledgeBaseMap> irq_lastforkphs;
    std::map<uint32_t /* pc */, uint32_t /* count */> irqfork_count;
    WritePeripheralMap write_phs;
    ReadPeripheralMap read_phs;          // map pair with count rather that value
    TypeFlagPeripheralMap type_flag_phs; // use to indicate control phs map but don't store the value
    TypeFlagPeripheralMap dt1_type_flag_phs; // use to indicate third kind of data registers
    TypeFlagPeripheralMap all_rw_phs;    // use to indicate control phs map but don't store the value
    TypeFlagPeripheralMap condition_phs; // record all phs which meet conditions
    TypeFlagPeripheralMap lock_t1_type_flag;
    TypeFlagPeripheralMap t0_type_flag_phs; // use to indicate which t0 phs have been read
    TypeFlagPeripheralMap t3_size_map;      // use to indicate t3 ph size
    std::map<uint32_t, std::map<uint32_t, uint32_t>> t3_value_count; // use to indicate t3 value count
    T1PeripheralMap symbolicpc_phs;         // 1 means this phs have been read as pc
    T1PeripheralMap symbolicpc_phs_fork_count;
    T0PeripheralMap t0_type_phs;
    T1BNPeripheralMap t1_type_phs;
    T1PeripheralMap pdata_type_phs; // for only one time reading becase t1 is stored in second time reading
    T1BNPeripheralMap pt1_type_phs;
    T1PeripheralMap
        pt1_type_flag_phs;            // 1 means this reg has never been read as seed; 2 means already been read as seed
    T1PeripheralMap t2_type_flag_phs; // If t2 or not (base on phaddr & pc)
    T2PeripheralMap pt2_type_flag_phs; // 1 means this reg has never been read as t2; 2 means already been read
    T2PeripheralMap t2_type_phs;
    TIRQCPeripheralMap tirqc_type_phs; // store the control ph values corresponding to the regs has
    TIRQCPeripheralMap etirqc_type_phs;
    TypeFlagPeripheralMap type_irq_flag;
    PeripheralForkCount ph_forks_count;
    std::map<uint32_t /* irq no */, std::deque<uint64_t>> hash_stack;
    TypeFlagPeripheralMap concrete_t3_flag;
    T3PeripheralMap t3_type_phs;
    std::deque<UniquePeripheral> current_irq_phs_value;
    AllKnowledgeBaseNoMap allcache_phs; // save every value for all phs read (once for each read)
    // TIRQSPeripheralMap tirqs_type_phs;
    // TWHCPeripheralMap twhc_type_phs; // twhc type
public:
    MyMultiSearcherState() {
        write_phs.clear();
    }

    virtual ~MyMultiSearcherState() {
    }

    static PluginState *factory(Plugin *, S2EExecutionState *) {
        return new MyMultiSearcherState();
    }

    TypeFlagPeripheralMap get_all_rw_phs() {
        return all_rw_phs;
    }

    // type flag
    void insert_type_flag_phs(uint32_t phaddr, uint32_t flag) {
        type_flag_phs[phaddr] = flag;
    }

    TypeFlagPeripheralMap get_type_flag_phs() {
        return type_flag_phs;
    }

    uint32_t get_type_flag_ph_it(uint32_t phaddr) {
        return type_flag_phs[phaddr];
    }


    void insert_lock_t1_type_flag(uint32_t phaddr, uint32_t flag) {
        lock_t1_type_flag[phaddr] = flag;
    }



    // data t1 for first time store
    void insert_pdata_type_phs(UniquePeripheral phc, uint32_t value) {
        pdata_type_phs[phc] = value;
    }

    T1PeripheralMap get_pdata_type_phs() {
        return pdata_type_phs;
    }


    T2PeripheralMap get_t2_type_phs() {
        return t2_type_phs;
    }



    void erase_t2_type_phs(UniquePeripheral phc) {
        t2_type_phs.erase(phc);
    }

    uint32_t get_t2_type_flag_ph_it(UniquePeripheral phc) {
        return t2_type_flag_phs[phc];
    }




    // t3
    void insert_concrete_t3_flag(uint32_t phaddr, uint32_t flag) {
        concrete_t3_flag[phaddr] = flag;
    }

    uint32_t get_concrete_t3_flag(uint32_t phaddr) {
        return concrete_t3_flag[phaddr];
    }

    uint32_t get_t3_type_ph_size(uint32_t phaddr) {
        return t3_type_phs[phaddr].size();
    }

    void insert_t3_type_ph_back(uint32_t phaddr, uint32_t value) {
        if (find(t3_type_phs[phaddr].begin(), t3_type_phs[phaddr].end(), value)
                == t3_type_phs[phaddr].end()) {
            t3_type_phs[phaddr].push_back(value);
            t3_value_count[phaddr][value] = 1;
        } else {
            t3_value_count[phaddr][value]++;
        }
    }

    void push_t3_type_ph_back(uint32_t phaddr, uint32_t value) {
        t3_type_phs[phaddr].push_back(value);
    }
    void clear_t3_type_phs(uint32_t phaddr) {
        t3_type_phs[phaddr].clear();
    }
    void erase_t3_type_ph_it(uint32_t phaddr, uint32_t value) {
        std::deque<uint32_t>::iterator itun = std::find(t3_type_phs[phaddr].begin(), t3_type_phs[phaddr].end(), value);
        t3_type_phs[phaddr].erase(itun);
    }

    uint32_t get_irq_flag_ph_it(uint32_t phaddr) {
        return type_irq_flag[phaddr];
    }


    uint64_t get_readphs_count(uint32_t phaddr) {
        return read_phs[phaddr].second;
    }

    ReadPeripheralMap get_readphs() {
        return read_phs;
    }


    // last fork conds
    void insert_last_fork_cond(uint32_t pc, std::vector<uint32_t> cond_values) {
        last_fork_cond = std::make_pair(pc, cond_values);
    }

    std::pair<uint32_t, std::vector<uint32_t>> get_last_fork_cond() {
        return last_fork_cond;
    }

    // last fork phs interrupt
    void irq_insertlastfork_phs(uint32_t irq_num, UniquePeripheral phc, uint64_t ch_value, NumPair value_no) {
        irq_lastforkphs[irq_num][phc][ch_value] = value_no;
    }

    AllKnowledgeBaseMap irq_getlastfork_phs(uint32_t irq_num) {
        return irq_lastforkphs[irq_num];
    }

    void irq_clearlastfork_phs(uint32_t irq_num) {
        irq_lastforkphs[irq_num].clear();
    }

    // last fork phs
    void insertlastfork_phs(UniquePeripheral phc, uint64_t ch_value, NumPair value_no) {
        lastforkphs[phc][ch_value] = value_no;
    }

    AllKnowledgeBaseMap getlastfork_phs() {
        return lastforkphs;
    }

    void clearlastfork_phs() {
        lastforkphs.clear();
    }

    // update current irq peripherals
    void insert_current_irq_values(uint32_t phaddr, uint32_t value) {
        current_irq_phs_value.push_back(std::make_pair(phaddr, value));
    }

    void clear_current_irq_values() {
        current_irq_phs_value.clear();
    }

    std::deque<UniquePeripheral> get_current_irq_values() {
        return current_irq_phs_value;
    }

    // cache phs order by no
    void insert_cachephs(uint32_t phaddr, uint64_t no, uint32_t value) {
        allcache_phs[phaddr][no] = value;
    }

    NumMap get_cache_phs(uint32_t phaddr) {
        return allcache_phs[phaddr];
    }

  
    // record all conditional phs
    void insert_condition_ph_it(uint32_t phaddr) {
        condition_phs[phaddr] = 1;
    }


    // record t3 max size map
    void insert_t3_size_ph_it(uint32_t phaddr, uint32_t size) {
        t3_size_map[phaddr] = size;
    }

    // update hash
    void insert_hashstack(uint32_t irq_no, uint64_t sum_hash) {
        hash_stack[irq_no].push_back(sum_hash);
    }

    void pop_hashstack(uint32_t irq_no) {
        hash_stack[irq_no].pop_back();
    }
};
}
 void MyMultiSearcher::updateState(S2EExecutionState *state) {
            //recordstate ()
            uint32_t curPc = state->regs()->getPc();//得到函数地址
            int ID=state->getID();
            //函数地址来代表函数
            //std::map<uint32_t ,std::vector<uint32_t> my_stateClasses;
            my_stateClasses[curPc].push_back(ID);
            m_top->removeState(state);
            m_top->addState(state);
        }
void MyMultiSearcher::initialize() {
    
            //s2e()->getCorePlugin()->onInitializationComplete.connect(sigc::mem_fun(*this, &MultiSearcher::onInitComplete));
            
            //s2e()->getExecutor()->setSearcher(this);
            //m_searchers = s2e()->getPlugin<Searchers::MultiSearcher>();
            //m_top = new CUPASearcherMyruleClass(this, level);
            S2EExecutionState *state=nullptr;
            //m_searchers->registerSearcher("MySearcher", m_top);
            t2_max_context=8;
            
            onARMFunctionConnection = s2e()->getPlugin<ARMFunctionMonitor>();
            onARMFunctionConnection->onARMFunctionCallEvent.connect(
                sigc::mem_fun(*this, &MyMultiSearcher::onARMFunctionCall));
            
            onStateForkConnection =s2e()->getCorePlugin()->onStateFork.connect(
                sigc::mem_fun(*this, &MyMultiSearcher::onFork));
            
            onARMFunctionConnection->onARMFunctionReturnEvent.connect(
                sigc::mem_fun(*this, &MyMultiSearcher::onARMFunctionReturn));
            
            onInvalidStateDectionConnection = s2e()->getPlugin<InvalidStatesDetection>();
            onInvalidStateDectionConnection->onInvalidStatesEvent.connect(
                sigc::mem_fun(*this, &MyMultiSearcher::onInvalidStatesDetection));
            updateState(state);

    
   
}



void MyMultiSearcher::onARMFunctionCall(S2EExecutionState *state, uint32_t caller_pc, uint64_t function_hash) {
    DECLARE_PLUGINSTATE(MyMultiSearcherState, state);
    if (state->regs()->getInterruptFlag()) {
        if (state->regs()->getExceptionIndex() > 15) {
            getDebugStream() << "irq num " << state->regs()->getExceptionIndex() << " caller PC = " << hexval(caller_pc)
                             << "\n";
            //updateIRQKB(state, state->regs()->getExceptionIndex(), 1);
        }
        plgState->insert_hashstack(state->regs()->getExceptionIndex(), function_hash);
    } else {
        plgState->insert_hashstack(0, function_hash);
    }
}
struct CmpByNo {
    bool operator()(const std::pair<uint64_t, uint32_t> &ph1, const std::pair<uint64_t, uint32_t> &ph2) {
        return ph1.first < ph2.first;
    }
};

}
void MyMultiSearcher::onARMFunctionReturn(S2EExecutionState *state, uint32_t return_pc) {
    DECLARE_PLUGINSTATE(MyMultiSearcherState, state);
    if (state->regs()->getInterruptFlag()) {
        plgState->pop_hashstack(state->regs()->getExceptionIndex());
    } else {
        plgState->pop_hashstack(0);
    }
}

void MyMultiSearcher::onLearningTerminationDetection(S2EExecutionState *state, bool *actual_end,
                                                             uint64_t tb_num) {
    DECLARE_PLUGINSTATE(MyMultiSearcherState, state);

    getInfoStream() << "Terminate live state:" << state->getID() << " tb num " << tb_num << "\n";

    for (auto itairq : already_used_irq_values) {
        // already wait for so many bbs
        if (*actual_end == true) {
            break;
        }
        // data regs do not count
        if (plgState->get_type_flag_ph_it(std::get<1>(itairq.first)) != T1 ||
            irq_data_phs[std::get<1>(itairq.first)] == 2) {
            continue;
        }

        if (itairq.second.size() != possible_irq_values[itairq.first].size() && possible_irq_values[itairq.first].size() > 1) {
            getWarningsStream() << "ph addr = " << hexval(std::get<1>(itairq.first))
                             << " pc = " << hexval(std::get<2>(itairq.first))
                             << " irq no = " << std::get<0>(itairq.first)
                             << " already trigger number of irq values = " << itairq.second.size()
                             << " total number of irq values = " << possible_irq_values[itairq.first].size()
                             << "\n";
            *actual_end = false;
            return;
        }
    }

    if (enable_fuzzing && auto_mode_switch) {
        
        getInfoStream() << " Mode auto switch from KB phase to dynamic phase!!\n";
        switchModefromLtoF(state);
        *actual_end = true;
    } else {
        //updateGeneralKB(state, 0, Valid);
        //saveKBtoFile(state, tb_num);
        g_s2e->getCorePlugin()->onEngineShutdown.emit();
        // Flush here just in case ~S2E() is not called (e.g., if atexit()
        // shutdown handler was not called properly).
        g_s2e->flushOutputStreams();
        exit(0);
    }
}
void MyMultiSearcher::switchModefromLtoF(S2EExecutionState *state) {
    cache_t2_type_phs.clear();
    cache_pt1_type_phs.clear();
    cache_t3_type_phs.clear();
    cache_tirqc_type_phs.clear();
    cache_tirqs_type_phs.clear();
    cache_type_irqc_flag.clear();
    cache_type_irqs_flag.clear();
    cache_type_flag_phs.clear();
    cache_t1_type_flag_phs.clear();
    cache_t2_type_flag_phs.clear();
    cache_all_cache_phs.clear();
    possible_irq_values.clear();

    onStateForkConnection.disconnect();
    onStateForkDecideConnection.disconnect();
    onStateSwitchConnection.disconnect();
    onInterruptExitonnection.disconnect();
    
    alive_points_count.clear();

    // TODO: updatge learning_mode_states in every kill and put the learning mode states to false states to kill
    onModeSwitch.emit(state, false);
    false_type_phs_fork_states.clear();
    for (auto learning_state : learning_mode_states) {
        if (learning_state != state) {
            std::string s;
            llvm::raw_string_ostream ss(s);
            ss << "Kill Unused Fork State "<< learning_state->getID() << " in learning mode before switch to fuzzing mode!\n";
            ss.flush();
            s2e()->getExecutor()->terminateState(*learning_state, s);
        }
    }
    learning_mode_states.clear();

}
void MyMultiSearcher::onInvalidStatesDetection(S2EExecutionState *state, uint32_t pc, InvalidStatesType type,
                                                       uint64_t tb_num) {
    DECLARE_PLUGINSTATE(MyMultiSearcherState, state);

    // record every termination points for alive point identification
    alive_points_count[state->regs()->getPc()]++;
    getDebugStream() << "kill pc = " << hexval(state->regs()->getPc()) << " lr = " << hexval(state->regs()->getLr())
        << " alive point count " << alive_points_count[state->regs()->getPc()] << "\n";
    if ((alive_points_count[state->regs()->getPc()] > t2_max_context
         || (alive_points_count[state->regs()->getPc()] > state->getID() / 3 && state->getID() > 10))
        && (type == DL1 || type == LL1) && !enable_fuzzing) {
        getWarningsStream() << "====KB extraction phase failed! Please add the alive point: "
                            << hexval(pc) <<" and re-run the learning parse====\n";
        exit(-1);
    }
    // remove current state in cache interrupt states
    if (irq_states.size() > 0) {
        auto itirqs = irq_states.begin();
        for (; itirqs != irq_states.end();) {
            if (*itirqs == state) {
                getDebugStream() << "delete currecnt state in irq states " << (*itirqs)->getID() << "\n";
                irq_states.erase(itirqs);
            } else {
                itirqs++;
            }
        }
    }

    // remove current state in cache learning mode states
    if (learning_mode_states.size() > 0) {
        auto itles = learning_mode_states.begin();
        for (; itles != learning_mode_states.end();) {
            if (*itles == state) {
                getDebugStream() << "delete current state in learning state " << (*itles)->getID() << "\n";
                learning_mode_states.erase(itles);
            } else {
                itles++;
            }
        }
    }

    
    // remove wrong value in external interrupt value pool
    if (!irq_no_new_branch_flag && state->regs()->getInterruptFlag()) {
        TypeFlagPeripheralMap type_flag_phs = plgState->get_type_flag_phs();
        for (auto &it : plgState->irq_getlastfork_phs(state->regs()->getExceptionIndex())) {
            for (auto &itch : it.second) {
                if (type_flag_phs[it.first.first] == T3) {
                    getDebugStream() << " t3 loop phs = " << hexval(it.first.first)
                                     << " pc = " << hexval(it.first.second) << " value = " << hexval(itch.second.second)
                                     << "\n";
                    break;
                } else if (type_flag_phs[it.first.first] == T1 && state->regs()->getExceptionIndex() > 15) {
                    IRQPhTuple uniqueirqsphs =
                        std::make_tuple(state->regs()->getExceptionIndex(), it.first.first, it.first.second);
                    std::deque<uint32_t>::iterator itirq =
                        std::find(possible_irq_values[uniqueirqsphs].begin(), possible_irq_values[uniqueirqsphs].end(),
                                  itch.second.second);
                    std::deque<uint32_t>::iterator itairq =
                        std::find(already_used_irq_values[uniqueirqsphs].begin(),
                                  already_used_irq_values[uniqueirqsphs].end(), itch.second.second);
                    if (itairq != already_used_irq_values[uniqueirqsphs].end()) {
                        already_used_irq_values[uniqueirqsphs].erase(itairq);
                    }
                    if (itirq != possible_irq_values[uniqueirqsphs].end()) {
                        possible_irq_values[uniqueirqsphs].erase(itirq);
                        impossible_irq_values[uniqueirqsphs].push_back(itch.second.second);
                        getDebugStream() << " remove irq phs = " << hexval(it.first.first)
                                         << " pc = " << hexval(it.first.second)
                                         << " value = " << hexval(itch.second.second) << "\n";
                        break;
                    }
                }
            }
        }
    }

    //// remove current state in cache fork states
    for (int i = 0; i < unsearched_condition_fork_states.size(); i++) {
        auto cfss = unsearched_condition_fork_states[i].begin();
        for (; cfss != unsearched_condition_fork_states[i].end();) {
            if (*cfss == state) {
                getDebugStream() << "delete current state in unused cache t1 state " << (*cfss)->getID() << "\n";
                unsearched_condition_fork_states[i].erase(cfss);
            } else {
                cfss++;
            }
        }
    }

    // remove states in same loop
    if ((!no_new_branch_flag && !state->regs()->getInterruptFlag()) ||
        (!irq_no_new_branch_flag && state->regs()->getInterruptFlag())) {
        if (unsearched_condition_fork_states.back().size() > 1) {
            for (int i = 1; i < unsearched_condition_fork_states.back().size();
                 ++i) { // last it is current state so not add current state
                false_type_phs_fork_states.push_back(unsearched_condition_fork_states.back()[i]);
                getDebugStream() << " remove useless loop fork state in above condition "
                                 << unsearched_condition_fork_states.back()[i]->getID()
                                 << " size = " << unsearched_condition_fork_states.back().size() << "\n";
            }
            std::vector<S2EExecutionState *> unsbfs;
            unsbfs.clear();
            unsbfs.push_back(unsearched_condition_fork_states.back()[0]);
            unsearched_condition_fork_states.pop_back();
            unsearched_condition_fork_states.push_back(unsbfs);
            fs = -1;
        }
    }

    if ((no_new_branch_flag && (!state->regs()->getInterruptFlag())) ||
        (irq_no_new_branch_flag && state->regs()->getInterruptFlag())) {
        unsearched_condition_fork_states.pop_back();
        if (unsearched_condition_fork_states.back().size() > 1) {
            for (int i = 1; i < unsearched_condition_fork_states.back().size();
                 ++i) { // last it is current state so not add current state
                false_type_phs_fork_states.push_back(unsearched_condition_fork_states.back()[i]);
                getDebugStream() << " remove useless loop fork state in above condition "
                                 << unsearched_condition_fork_states.back()[i]->getID()
                                 << " size = " << unsearched_condition_fork_states.back().size() << "\n";
            }
            std::vector<S2EExecutionState *> unsbfs;
            unsbfs.clear();
            unsbfs.push_back(unsearched_condition_fork_states.back()[0]);
            unsearched_condition_fork_states.pop_back();
            unsearched_condition_fork_states.push_back(unsbfs);
            fs = -1;
        }
    }

    // push all useless states together and kill.
    if (!state->regs()->getInterruptFlag()) {
        for (auto firqs : irq_states) {
            if (find(false_type_phs_fork_states.begin(), false_type_phs_fork_states.end(), firqs) ==
                false_type_phs_fork_states.end()) {
                getDebugStream() << "Kill Fork State in interrupt:" << firqs->getID() << "\n";
                false_type_phs_fork_states.push_back(firqs);
            }
        }
        fs = -1;
        irq_states.clear();
    }
}
void SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c) {
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2) {
        v.push_back(s.substr(pos1, pos2 - pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if (pos1 != s.length())
        v.push_back(s.substr(pos1));
}
bool MyMultiSearcher::getPeripheralExecutionState(std::string variablePeripheralName, uint32_t *phaddr,
                                                          uint32_t *pc, uint64_t *ch_value, uint64_t *no) {
    boost::smatch what;
    if (!boost::regex_match(variablePeripheralName, what, MyMultiSearcherRegEx)) {
        getWarningsStream() << "match false"
                            << "\n";
        exit(0);
        return false;
    }

    if (what.size() != 4) {
        getWarningsStream() << "wrong size = " << what.size() << "\n";
        exit(0);
        return false;
    }

    std::string peripheralAddressStr = what[1];
    std::string pcStr = what[2];
    std::string noStr = what[3];

    std::vector<std::string> v;
    SplitString(peripheralAddressStr, v, "_");
    *phaddr = std::stoull(v[0].c_str(), NULL, 16);
    *pc = std::stoull(v[1].c_str(), NULL, 16);
    *ch_value = std::stoull(pcStr.c_str(), NULL, 16);
    *no = std::stoull(noStr.c_str(), NULL, 10);

    return true;
}
bool comp(std::vector<uint32_t> &v1, std::vector<uint32_t> &v2) {
    for (int i = 0; i < v2.size(); i++) {
        if (std::find(v1.begin(), v1.end(), v2[i]) == v1.end())
            return false;
    }
    return true;
}

void MyMultiSearcher::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                                     const std::vector<klee::ref<klee::Expr>> &newConditions) {
    DECLARE_PLUGINSTATE(MyMultiSearcherState, state);
    std::map<uint32_t, AllKnowledgeBaseMap> cachefork_phs;
    cachefork_phs.clear();
    bool T3_flag = false;

    std::vector<uint32_t> fork_states_values;
    fork_states_values.clear();

    for (int k = newStates.size() - 1; k >= 0; --k) {
        DECLARE_PLUGINSTATE(MyMultiSearcherState, newStates[k]);
        ReadPeripheralMap read_size_phs = plgState->get_readphs();
        ArrayVec results;

        findSymbolicObjects(newConditions[0], results);
        for (int i = results.size() - 1; i >= 0; --i) { // one cond multiple sym var
            uint32_t phaddr;
            uint32_t pc;
            uint64_t ch_value;
            uint64_t no;
            auto &arr = results[i];
            std::vector<unsigned char> data;

            getPeripheralExecutionState(arr->getName(), &phaddr, &pc, &ch_value, &no);

            // getDebugStream() << "The symbol name of value is " << arr->getName() << "\n";
            for (unsigned s = 0; s < arr->getSize(); ++s) {
                ref<Expr> e = newStates[k]->concolics->evaluate(arr, s);
                if (!isa<ConstantExpr>(e)) {
                    getWarningsStream() << "Failed to evaluate concrete value\n";
                    pabort("Failed to evaluate concrete value");
                }

                uint8_t val = dyn_cast<ConstantExpr>(e)->getZExtValue();
                data.push_back(val);
            }

            uint32_t condConcreteValue =
                data[0] | ((uint32_t) data[1] << 8) | ((uint32_t) data[2] << 16) | ((uint32_t) data[3] << 24);

            UniquePeripheral uniquePeripheral = std::make_pair(phaddr, pc);
            uint64_t LSB = ((uint64_t) 1 << (read_size_phs[phaddr].first * 8));
            uint32_t value = condConcreteValue & (LSB - 1);
            fork_states_values.push_back(value);

            // divide irq data regs with sr and cr regs
            if (newStates[k]->regs()->getInterruptFlag()) {
                if (newStates[k]->regs()->getExceptionIndex() > 15) {
                    // used for irq sr type judgement
                    plgState->insert_current_irq_values(phaddr, value);
                }
                irq_data_phs[phaddr] = 1;
            }
            // insert p flag for external irq
            if ((newStates[k]->regs()->getInterruptFlag() && newStates[k]->regs()->getExceptionIndex() > 15) ||
                (plgState->get_irq_flag_ph_it(phaddr) == 1 || plgState->get_irq_flag_ph_it(phaddr) == 2)) {
                getInfoStream(newStates[k]) << " Note: all possible IRQ value of phaddr = " << hexval(phaddr)
                                                << " pc = " << hexval(pc) << " value = " << hexval(value) << "\n";
                if (possible_irq_srs.find(std::make_pair(phaddr, pc)) != possible_irq_srs.end()) {
                    // save all possible value for t3 phs
                    IRQPhTuple uniqueirqsphs =
                        std::make_tuple(possible_irq_srs[std::make_pair(phaddr, pc)], phaddr, pc);
                    if (plgState->get_type_flag_ph_it(phaddr) == T1) {
                        if (find(possible_irq_values[uniqueirqsphs].begin(), possible_irq_values[uniqueirqsphs].end(),
                                 value) == possible_irq_values[uniqueirqsphs].end() &&
                            ((value & 0xffffffff) != 0xf0f0f0f)) {
                            if (find(impossible_irq_values[uniqueirqsphs].begin(),
                                     impossible_irq_values[uniqueirqsphs].end(),
                                     value) == impossible_irq_values[uniqueirqsphs].end()) {
                                getInfoStream(newStates[k]) << " Note: New IRQ value of phaddr = " << hexval(phaddr)
                                                                << " pc = " << hexval(pc)
                                                                << " value = " << hexval(value) << "\n";
                                possible_irq_values[uniqueirqsphs].push_back(value);
                            }
                        }
                    }
                } else {
                    getDebugStream() << "T0 type\n";
                }
            }

            // TODO: No. should be map only in IRQ mode
            if (cachefork_phs[k].count(uniquePeripheral) > 0 &&
                !(newStates[k]->regs()->getInterruptFlag() && newStates[k]->regs()->getExceptionIndex() > 15)) {
                if (cachefork_phs[k][uniquePeripheral].count(ch_value) > 0) {
                    if ((cachefork_phs[k][uniquePeripheral][ch_value].first != no &&
                         cachefork_phs[k][uniquePeripheral][ch_value].second != value &&
                         plgState->get_type_flag_ph_it(phaddr) != T0) ||
                        T3_flag) {
                        T3_flag = true;
                        plgState->insert_type_flag_phs(phaddr, T3);
                        plgState->insert_t3_type_ph_back(phaddr, value);
                        if (plgState->get_t2_type_flag_ph_it(uniquePeripheral) == T2) {
                            plgState->erase_t2_type_phs(uniquePeripheral);
                            getInfoStream(newStates[k]) << " Note: t2 change to t3 phaddr = " << hexval(phaddr)
                                                            << " size = " << plgState->get_t3_type_ph_size(phaddr)
                                                            << "\n";
                        } else {
                            getInfoStream(newStates[k]) << " Note: t1 change to t3 phaddr = " << hexval(phaddr)
                                                            << " size = " << plgState->get_t3_type_ph_size(phaddr)
                                                            << "\n";
                        }
                    }
                }
            }

            // update cachefork after T3 check
            cachefork_phs[k][uniquePeripheral][ch_value] = std::make_pair(no, value);
            T2Tuple uniquehashPeripheral = std::make_tuple(phaddr, pc, ch_value);
            if (find(all_fork_states_value_map[uniquehashPeripheral].begin(), all_fork_states_value_map[uniquehashPeripheral].end(), value)
                    == all_fork_states_value_map[uniquehashPeripheral].end()) {
                all_fork_states_value_map[uniquehashPeripheral].push_back(value);
                if (all_fork_states_value_map[uniquehashPeripheral].size() > 2) {
                    getInfoStream() << " Find mulit value phaddr = " << hexval(phaddr)
                        << " size = " << all_fork_states_value_map[uniquehashPeripheral].size() << "\n";
                    mulit_value_dr[phaddr] = 1;
                }
            }
            plgState->insert_cachephs(phaddr, no, value);
            plgState->insert_condition_ph_it(phaddr);
            getInfoStream(newStates[k]) << " all cache phaddr = " << hexval(phaddr) << " pc = " << hexval(pc)
                                            << " value = " << hexval(value) << " no = " << no
                                            << " width = " << hexval(read_size_phs[phaddr].first) << "\n";

            if (plgState->get_type_flag_ph_it(phaddr) == T3) {
                plgState->insert_t3_type_ph_back(phaddr, value);
                plgState->insert_t3_size_ph_it(phaddr, plgState->get_readphs_count(phaddr));
                if (plgState->get_concrete_t3_flag(phaddr) == 1 && state == newStates[k]) {
                    ConcreteT3Regs(newStates[k]);
                } else if ((plgState->get_t3_type_ph_size(phaddr) > 5 ||
                            plgState->get_readphs_count(phaddr) >= t3_max_symbolic_count) &&
                           state == newStates[k]) {
                    std::vector<std::pair<uint64_t, uint32_t>> ituncaches;
                    ituncaches.clear();
                    for (auto &itun : plgState->get_cache_phs(phaddr)) {
                        ituncaches.push_back(std::make_pair(itun.first, itun.second));
                    }
                    std::sort(ituncaches.begin(), ituncaches.end(), CmpByNo());
                    plgState->clear_t3_type_phs(phaddr);
                    for (auto ituncache : ituncaches) {
                        plgState->push_t3_type_ph_back(phaddr, ituncache.second);
                    }
                    getWarningsStream(newStates[k]) << " Note: concrete t3 phaddr = " << hexval(phaddr) << "\n";
                    plgState->insert_concrete_t3_flag(phaddr, 1);
                    ConcreteT3Regs(newStates[k]);
                }
            } else {
                if (newStates[k]->regs()->getInterruptFlag() == 0) {
                    getDebugStream(newStates[k]) << " backup all T0 T1 phaddr " << hexval(phaddr)
                                                 << " value = " << hexval(value) << "\n";
                    plgState->insert_pdata_type_phs(uniquePeripheral, value);
                    if (plgState->get_type_flag_ph_it(phaddr) == T1 && value != 0 && newStates[k] == state) {
                        plgState->insert_lock_t1_type_flag(phaddr, 1);
                        getDebugStream() << "Note: lock t1 " << hexval(phaddr) << "\n";
                    }
                }
            }

            // update path map
            if (newStates[k] == state) {
                all_searched_path_map[newStates[k]->getID()] = 1;
            } else {
                all_path_map[newStates[k]->getID()] = 1;
            }

        } // each condition

        // push fork states in interrupt
        if (newStates[k]->regs()->getInterruptFlag()) {
            if (newStates[k] != state) {
                getDebugStream() << "push irq state" << newStates[k]->getID() << "\n";
                irq_states.push_back(newStates[k]);
            }
        }
        // push states to learning mode for auto state transfer
        if (find(learning_mode_states.begin(), learning_mode_states.end(), newStates[k]) ==
            learning_mode_states.end()) {
            learning_mode_states.push_back(newStates[k]);
        }

    } // each new State

    uint32_t current_pc = state->regs()->getPc();
    std::pair<uint32_t, std::vector<uint32_t>> last_fork_cond = plgState->get_last_fork_cond();
    plgState->insert_last_fork_cond(current_pc, fork_states_values);
    if (last_fork_cond.first == current_pc && comp(last_fork_cond.second, fork_states_values) &&
        comp(fork_states_values, last_fork_cond.second)) {
        for (int k = newStates.size() - 1; k >= 0; --k) {
            DECLARE_PLUGINSTATE(MyMultiSearcherState, newStates[k]);
            // only update kb for new condition
            if (newStates[k]->regs()->getInterruptFlag()) {
                plgState->irq_clearlastfork_phs(newStates[k]->regs()->getExceptionIndex());
                for (auto &it : cachefork_phs[k]) {
                    for (auto &itch : it.second) {
                        plgState->irq_insertlastfork_phs(newStates[k]->regs()->getExceptionIndex(), it.first,
                                                         itch.first, itch.second);
                    }
                }
            } else {
                plgState->clearlastfork_phs();
                for (auto &it : cachefork_phs[k]) {
                    for (auto &itch : it.second) {
                        plgState->insertlastfork_phs(it.first, itch.first, itch.second);
                    }
                }
            }
            // push back new loop state
            if (newStates[k] != state) {
                unsearched_condition_fork_states.back().push_back(newStates[k]);
            }
        }
        getWarningsStream(state) << "fork cond in the loop !!" << hexval(current_pc) << "\n";
        return;
    } else {
        // set fork flag
        if (state->regs()->getInterruptFlag()) {
            irq_no_new_branch_flag = false;
        } else {
            no_new_branch_flag = false;
        }

        for (int k = newStates.size() - 1; k >= 0; --k) {
            // push back new states
            if (newStates[k] != state) {
                std::vector<S2EExecutionState *> condition_fork_states; // forking states in each condition
                condition_fork_states.clear();
                condition_fork_states.push_back(newStates[k]);
                unsearched_condition_fork_states.push_back(condition_fork_states);
            }
        }
    }

    // update KB
    for (int k = newStates.size() - 1; k >= 0; --k) {
        DECLARE_PLUGINSTATE(MyMultiSearcherState, newStates[k]);
        // cache the possiable status phs in corresponding state and insert lask fork state for further choices
        // interrupt mode
        if (newStates[k]->regs()->getInterruptFlag()) {
            if (newStates[k]->regs()->getExceptionIndex() > 15) {
                getDebugStream() << " donot store irq phs \n";
            } else {
                if (newStates[k] == state) {
                   // updateGeneralKB(newStates[k], newStates[k]->regs()->getExceptionIndex(), Valid);
                }
            }
            plgState->irq_clearlastfork_phs(newStates[k]->regs()->getExceptionIndex());
            for (auto &it : cachefork_phs[k]) {
                for (auto &itch : it.second) {
                    plgState->irq_insertlastfork_phs(newStates[k]->regs()->getExceptionIndex(), it.first, itch.first,
                                                     itch.second);
                }
            }
        } else { // normal mode
            if (newStates[k] == state) {
                //updateGeneralKB(newStates[k], 0, Valid);
            } // current state
            plgState->clearlastfork_phs();
            for (auto &it : cachefork_phs[k]) {
                for (auto &itch : it.second) {
                    plgState->insertlastfork_phs(it.first, itch.first, itch.second);
                }
            }
        }
    }
}
bool  MyMultiSearcher::ConcreteT3Regs(S2EExecutionState *state) {

    for (unsigned i = 0; i < 13; ++i) {
        unsigned offset = offsetof(CPUARMState, regs[i]);
        target_ulong concreteData;

        klee::ref<klee::Expr> expr = state->regs()->read(offset, sizeof(concreteData) * 8);
        if (!isa<klee::ConstantExpr>(expr)) {
            // evaluate symbolic regs
            klee::ref<klee::ConstantExpr> ce;
            ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(expr));
            concreteData = ce->getZExtValue();
            getDebugStream() << " symbolic reg" << i << " = " << expr << " concrete value = " << hexval(concreteData)
                             << "\n";
            state->regs()->write(offset, &concreteData, sizeof(concreteData));
        }
    }

    return true;
}

    

}


} // namespace hw
} // namespace plugins
} // namespace s2e
