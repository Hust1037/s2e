
#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include <iostream>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "TraceMonitor.h"

#include <llvm/Support/CommandLine.h>
//TraceMonitor
namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InvalidStatesDetection, "Kill dead loops of executed translation blocks", "InvalidStatesDetection");

namespace {

class InvalidStatesDetectionState : public PluginState {
private:
    CacheConregs cacheconregs;
    CacheConregs loopconregs;
    // add count limit
    std::map<UniquePcRegMap, uint32_t /* count */> reg_loop_count;
    std::map<UniquePcRegMap, std::deque<int> /* reg_value */> re_reg_map;
    std::map<uint32_t, uint32_t /* count */> kill_point_count;
    uint32_t max_cache_tb_num; // total tb number in cache
    uint64_t max_loop_limit;
    bool loopcmpflag;
    bool modeflag;       // only kill in symbolic mode
    uint64_t new_tb_num; // new tb number in per state
    uint64_t re_tb_num;  // repeat tb number in per state
    uint64_t tb_num;     // all tb number in per state
    bool enable_kill;    // indicate all external irqs have been invoked at once;
    TBCounts new_tb_map;
    uint32_t current_irq_num;

public:
    virtual InvalidStatesDetectionState *clone() const {
        return new InvalidStatesDetectionState(*this);
    }

    InvalidStatesDetectionState() {
        tb_num = 0;
        new_tb_num = 0;
        re_tb_num = 0;
        loopcmpflag = false;
        enable_kill = false;
        cacheconregs.clear();
        loopconregs.clear();
        new_tb_map.clear();
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new InvalidStatesDetectionState();
    }

    virtual ~InvalidStatesDetectionState() {
    }

    void reset_allcache() {
        tb_num = 0;
        re_tb_num = 0;
        loopcmpflag = false;
        enable_kill = false;
        cacheconregs.clear();
        loopconregs.clear();
    }

    void inckpcount(uint32_t pc) {
        kill_point_count[pc]++;
    }

    uint32_t getkpcount(uint32_t pc) {
        return kill_point_count[pc];
    }

    // long loop judgement
    void setmaxloopnum(uint64_t max_loop_tb_num) {
        max_loop_limit = max_loop_tb_num;
    }

    bool judgelongloopregs(UniquePcRegMap uniquepcregmap, uint32_t reg_value) {
        re_reg_map[uniquepcregmap].push_back(reg_value);
        if (re_reg_map[uniquepcregmap].size() > 2) {
            if (std::abs(re_reg_map[uniquepcregmap][2] - re_reg_map[uniquepcregmap][1]) == 1) {
                reg_loop_count[uniquepcregmap]++;
                if (reg_loop_count[uniquepcregmap] > (max_loop_limit - 5)) {
                    reg_loop_count[uniquepcregmap] = 0;
                    return true;
                }
            } else {
                // printf("re_reg_map[uniquepcregmap][2] = 0x%x, re_reg_map[uniquepcregmap][1] = 0x%x\n",
                // re_reg_map[uniquepcregmap][2], re_reg_map[uniquepcregmap][1]);
                reg_loop_count[uniquepcregmap] = 0;
            }
            re_reg_map[uniquepcregmap].pop_front();
        }
        return false;
    }

    void setenablekill(bool enablekill) {
        enable_kill = enablekill;
    }

    bool getenablekill() {
        return enable_kill;
    }

    void assignloopregs(uint32_t i) {
        // already judge first one continue will the second
        loopconregs.assign(cacheconregs.begin() + i, cacheconregs.end());
    }

    ConRegs getcurloopregs() {
        return loopconregs.at(0);
    }

    void poploopregs() {
        loopconregs.pop_front();
    }

    uint32_t getloopsize() {
        return loopconregs.size();
    }

    void setloopflag(bool loop_cmp_flag) {
        loopcmpflag = loop_cmp_flag;
    }

    bool getloopflag() {
        return loopcmpflag;
    }
    /// concrete mode judgement
    void setmodeflag(bool mode_flag) {
        modeflag = mode_flag;
    }

    bool getmodeflag() {
        return modeflag;
    }

    void setcachenum(uint32_t cache_tb_num) {
        max_cache_tb_num = cache_tb_num;
    }

    bool inctbnum(uint32_t cur_pc) {
        ++tb_num;
        if (new_tb_map[cur_pc] < 1) {
            ++new_tb_num;
            ++new_tb_map[cur_pc];
            re_tb_num = 0;
            return true;
        } else {
            ++re_tb_num;
            return false;
        }
    }

    void inctbnum2(uint32_t cur_pc) {
        if (new_tb_map[cur_pc] < 1) {
            ++new_tb_num;
            ++new_tb_map[cur_pc];
        }
    }

    uint64_t getnewtbnum() {
        return new_tb_num;
    }

    uint64_t gettbnum() {
        return tb_num;
    }

    uint64_t getretbnum() {
        return re_tb_num;
    }

    void inserttbregs(ConRegs regs) {
        if (cacheconregs.size() < max_cache_tb_num) {
            cacheconregs.push_back(regs);//插入一个向量
        } else {
            cacheconregs.pop_front();
            cacheconregs.push_back(regs);
        }
    }

    uint32_t getcachesize() {
        return cacheconregs.size();
    }

    ConRegs getcurtbregs(uint32_t cachePos) {
        return cacheconregs.at(cachePos);
    }

    uint32_t getcurtbpc(uint32_t cachePos) {
        return cacheconregs.at(cachePos)[0];
    }

    uint32_t getcurtbmode(uint32_t cachePos) {
        return cacheconregs.at(cachePos)[1];
    }

    uint32_t getcurtbregssize(uint32_t cachePos) {
        return cacheconregs.at(cachePos).size();
    }

    void insert_current_irq_num(uint32_t irq_num) {
        current_irq_num = irq_num;
    }
};
}

void InvalidStatesDetection::initialize() {
	//std::vector<uint32_t> conregs = getRegs(state, pc);
	 //plgState->inserttbregs(conregs);
	 //每一次运行记录寄存器的数值
	cache_tb_num = s2e()->getConfig()->getInt(getConfigKey() + ".bb_inv1", 20, &ok);
    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
        sigc::mem_fun(*this, &InvalidStatesDetection::onTranslateBlockEnd));
    blockStartConnection = s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &InvalidStatesDetection::onTranslateBlockStart));
}


void InvalidStatesDetection::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                 TranslationBlock *tb, uint64_t pc, bool staticTarget,
                                                 uint64_t staticTargetPc) {
    signal->connect(
        sigc::bind(sigc::mem_fun(*this, &InvalidStatesDetection::onInvalidLoopDetection), (unsigned) tb->se_tb_type));
}

void InvalidStatesDetection::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                   TranslationBlock *tb, uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &InvalidStatesDetection::onKillandAlivePoints));
}

template <typename T> static bool getConcolicValue(S2EExecutionState *state, unsigned offset, T *value) {
    auto size = sizeof(T);

    klee::ref<klee::Expr> expr = state->regs()->read(offset, size * 8);
    if (isa<klee::ConstantExpr>(expr)) {
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(expr);
        *value = ce->getZExtValue();
        return true;
    }

    // evaluate symobolic regs
    klee::ref<klee::ConstantExpr> ce;
    ce = dyn_cast<klee::ConstantExpr>(state->concolics->evaluate(expr));
    *value = ce->getZExtValue();
    return true;
}

static std::vector<uint32_t> getRegs(S2EExecutionState *state, uint32_t pc) {
    std::vector<uint32_t> conregs;
    bool mode = g_s2e_fast_concrete_invocation;

    conregs.push_back(pc);
    conregs.push_back(mode);
    for (unsigned i = 0; i < 15; ++i) {
        unsigned offset = offsetof(CPUARMState, regs[i]);
        target_ulong concreteData;

        // if (state->regs()->read(offset, &concreteData, sizeof(concreteData), false)) {
        getConcolicValue(state, offset, &concreteData);
        conregs.push_back(concreteData);
        // }
    }

    return conregs;
}


void InvalidStatesDetection::onInvalidStatesKill(S2EExecutionState *state, uint64_t pc, InvalidStatesType type,
                                                 std::string reason_str) {
    DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);

    onInvalidStatesEvent.emit(state, pc, type, plgState->getnewtbnum());
    std::string s;
    llvm::raw_string_ostream ss(s);
    ss << reason_str << state->getID() << " pc = " << hexval(state->regs()->getPc()) << " tb num "
       << plgState->getnewtbnum() << "\n";
    ss.flush();
    s2e()->getExecutor()->terminateState(*state, s);
}



void InvalidStatesDetection::onKillandAlivePoints(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);
    // kill points defined by users
    for (auto kill_point : kill_points) {
        if (kill_point == pc) {
            plgState->inckpcount(pc);
            if (plgState->getkpcount(pc) > 0) {
                kill_point_flag = true;
                break;              
            }
        }
    }

    // have alive points or not
    for (auto alive_point : alive_points) {
        if (alive_point == pc) {
            alive_point_flag = true;
            break;
        }
    }
}


void InvalidStatesDetection::onInvalidLoopDetection(S2EExecutionState *state, uint64_t pc, unsigned source_type) {
    DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);
    // update re and new tb number
	plgState->setcachenum(cache_tb_num);
    std::vector<uint32_t> conregs = getRegs(state, pc); 
    getInfoStream(state) << state->regs()->getInterruptFlag() << " current pc = " << hexval(pc) << " re tb num "
                             << plgState->getretbnum() << " concrete mode: " << conregs[1] << "\n";
	std::vector<uint32_t> loopregs = plgState->getcurloopregs();
	int boolflag=0;
	int k=0;
	for(k=0;k<conregs.size();k++)
	{
		if(conregs[k]==loopregs[k])
		{
			continue;
		}
		else{
			boolflag=1;
			break;
		}
	}
	if(!boolflag)//说明存在15个寄存器全部相同的情况
	{
		std::string reason_str = "Kill State due to dead loop (multi-tbs):";
        onInvalidStatesKill(state, pc, DL2, reason_str);
	}
	else{
		plgState->inserttbregs(conregs);
		return;
	}
}

// only used in unit test addition confirmation
/* static bool unittesthook(S2EExecutionState *state, uint32_t pc) { */
// std::vector<uint32_t> conregs;

// for (unsigned i = 0; i < 15; ++i) {
// unsigned offset = offsetof(CPUARMState, regs[i]);
// target_ulong concreteData;

// //if (state->regs()->read(offset, &concreteData, sizeof(concreteData), false)) {
// getConcolicValue(state, offset, &concreteData);
// conregs.push_back(concreteData);
// // }
// }

// if (pc == 0x800306c || pc == 0x80034b6 || pc == 0x8003058 || pc == 0x8001c6e) {
// for (int j = 0; j < 13; j++) {
// g_s2e->getDebugStream() << hexval(pc) << "Check  point R" << j << " = " << hexval(conregs[j]) << "\n";
// }
// }

// return true;

/* } */

// only used for addtional log
/*void InvalidStatesDetection::recordTBMap(S2EExecutionState *state) {*/
// DECLARE_PLUGINSTATE(InvalidStatesDetectionState, state);
// std::string fileName;
// fileName = s2e()->getOutputDirectory() + "/" + "state" + std::to_string(state->getID()) + "_tb_map.dat";
// std::ofstream fTBmap;
// fTBmap.open(fileName, std::ios::out | std::ios::trunc);

// for (auto ittb : plgState->getuniquetbmap()) {
// fTBmap << "tb : " << hexval(ittb.first) << std::endl;;
//}

// fTBmap.close();
/*}*/

} // namespace plugins
} // namespace s2e
