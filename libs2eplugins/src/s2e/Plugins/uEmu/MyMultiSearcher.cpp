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
#include<stack>
#include <s2e/opcodes.h>
#include <klee/Executor.h>
#include <klee/Searcher.h>
#include "MyMultiSearcher.h"
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <llvm/Support/CommandLine.h>

using namespace klee;

namespace {
llvm::cl::opt<bool> DebugSymbHw("debug-symbolic-hardware", llvm::cl::init(true));
}

namespace s2e {
namespace plugins {


//------------自定义全局变量
uint32_t record_call_pc;
uint32_t record_return_pc;

S2EExecutionState *my_current_state;
S2E_DEFINE_PLUGIN(MyMultiSearcher, "MyMultiSearcher S2E plugin", "MyMultiSearcher",
                   "ARMFunctionMonitor");
S2EExecutionState *g_s2e_state = nullptr;
namespace {
class MyMultiSearcherState : public PluginState {
private:
    
public:
    MyMultiSearcherState() {
       // write_phs.clear();
    }

    virtual ~MyMultiSearcherState() {
    }

    static PluginState *factory(Plugin *, S2EExecutionState *) {
        return new MyMultiSearcherState();
    }
    MyMultiSearcherState *clone() const {
        return new MyMultiSearcherState(*this);
    }
};
}
//update函数在remove和fork时有
 void MyMultiSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                               const klee::StateSet &removedStates) {
            //recordstate ()
            //函数地址来代表函数
            //std::map<uint32_t ,std::vector<uint32_t> my_stateClasses;
            //std::map<uint32_t,std::vector<klee::ExecutionState *>> my_state_N_ID;//记录call地址下函数中所有遍历的state
            S2EExecutionState *current_s = static_cast<S2EExecutionState *>(current);
            int ID=current_s->getID();
            //int add_flag=0;//查看新增的状态是否在map中
             //current id 和 add进行对比 比如如果current id=1，但是addstate的id是2说明 add的state还没有进行遍历
            foreach2 (ait, addedStates.begin(), addedStates.end()){
               
                int add_ID;
                S2EExecutionState *addedState = static_cast<S2EExecutionState *>(*ait);
                add_ID=addedState->getID();
                if(add_ID==ID){
                    continue;
                }
                else{
                    my_stateClasses[record_call_pc].push_back(add_ID);
                    my_state_N_ID[record_call_pc].push_back(addedState);
                }
            }
             int i=0;
             int j=0;
            //remove中 一个function中有1234567，遍历remove(StateSet)中有67.就在自己的map中进行维护将6和7去掉
            for(std::vector<int>::iterator it=my_stateClasses[record_call_pc].begin();it!=my_stateClasses[record_call_pc].end();it++){
                int R_ID;
                R_ID=*it;
                foreach2 (ait, removedStates.begin(), removedStates.end()){
                    int remove_ID;
                    
                    S2EExecutionState *removedState = static_cast<S2EExecutionState *>(*ait);
                    remove_ID=removedState->getID();
                    if(R_ID==remove_ID)
                    {
                       
                        my_stateClasses[record_call_pc].erase(my_stateClasses[record_call_pc].begin()+i);
                        //std::vector<S2EExecutionState::ExecutionState *>::iterator cdss=my_stateClasses[record_call_pc].begin()+j;
                        //my_state_N_ID[record_call_pc].erase(cdss);
                    }
                    j++;
                }
                i++;
            }
            //std::vector<S2EExecutionState::ExecutionState *> add_state_exc;//用于在update记录的时候，去掉current和remove里面的状态用于select；
            foreach2 (ait, addedStates.begin(), addedStates.end()){
                int A_flag=0;
                S2EExecutionState *addedState = static_cast<S2EExecutionState *>(*ait);
                foreach2 (ait_R, removedStates.begin(), removedStates.end())
                {
                    S2EExecutionState *removedState = static_cast<S2EExecutionState *>(*ait_R);
                    if(addedState!=removedState)
                        continue;

                    else
                    {   A_flag=1;
                        break;
                    }
                }
                if(!A_flag&&addedState!=current)
                    add_state_exc.push_back(addedState);//
                
            }
            
            
            
           
        }
void MyMultiSearcher::initialize() {
    

            //s2e()->getCorePlugin()->onInitializationComplete.connect(sigc::mem_fun(*this, &MyMultiSearcher::onInitComplete)); 
            //s2e()->getExecutor()->setSearcher(this);
            //m_searchers = s2e()->getPlugin<Searchers::MultiSearcher>();
            //m_top = new CUPASearcherMyruleClass(this, level);
            //S2EExecutionState *state=nullptr;
            //m_searchers->registerSearcher("MySearcher", m_top);
            //exit_pc=0x08009260;//退出地址
            onARMFunctionConnection = s2e()->getPlugin<ARMFunctionMonitor>();
            onARMFunctionConnection->onARMFunctionCallEvent.connect(
                sigc::mem_fun(*this, &MyMultiSearcher::onARMFunctionCall));
            
            onStateForkConnection =s2e()->getCorePlugin()->onStateFork.connect(
                sigc::mem_fun(*this, &MyMultiSearcher::onFork));
            
            onARMFunctionConnection->onARMFunctionReturnEvent.connect(
                sigc::mem_fun(*this, &MyMultiSearcher::onARMFunctionReturn));
            
            //onInvalidStateDectionConnection = s2e()->getPlugin<InvalidStatesDetection>();
            //onInvalidStateDectionConnection->onInvalidStatesEvent.connect(
             //   sigc::mem_fun(*this, &MyMultiSearcher::onInvalidStatesDetection));
            my_current_state=nullptr;

}

 
//记录功能
//void MyMultiSearcher::updateState(S2EExecutionState *state) {
    //m_top->removeState(state);
    //m_top->addState(state);
//}
//选择下一个state在selectstate的时候根据map里面的数据选择要执行的状态
klee::ExecutionState &MyMultiSearcher::selectState() {
 
    uint32_t PC;
    PC=my_current_state->regs()->getPc();//g_s2e
    S2EExecutionState *return_s=nullptr;
    //如果condition下面的两个状态全部被遍历后，就直接删除map结构里面，因为condition的地址是不会发生变化的
    /*
    // std::pair<S2EExecutionState::ExecutionState *,S2EExecutionState::ExecutionState *> it2= mycondition_N_ID[record_call_pc][PC];
    // for(std::vector<S2EExecutionState::ExecutionState *>::iterator it= add_state_exc.begin();it!= add_state_exc.end();it++)
    // {
    //      S2EExecutionState::ExecutionState *first,*second;
        
    //     first=it2.first;
    //     second=it2.second;
    //     if(first==*it)
    //     {
    //         //klee::ExecutionState *addedState = static_cast<klee::ExecutionState *>(*it);
    //         return *addedState;
    //     }
    //     else if(second==*it)
    //     {
    //         //klee::ExecutionState *addedState = static_cast<klee::ExecutionState *>(*it);
    //         return *addedState;
    //     }
    // }*/
    //return出来的时候查看当前路径的ID是在哪一个conditionPC里面，找到它之后返回他的另一个，在大的map的循环,
    //return时候记录的state还有onfork的时候记录的PC
    std::map<uint32_t,std::vector<S2EExecutionState *>>::iterator it;
    for(it=fork_condition_class_copy[record_call_pc].begin();it!=fork_condition_class_copy[record_call_pc].end();it++)
    {
        
        std::vector<S2EExecutionState *> temp;
        temp=it->second;
        uint32_t conditionPC=it->first;
        if(temp.size()!=0){

            S2EExecutionState *f,*s;
            f=temp[0];
            s=temp[1];
            //还得查看对应的另外一项是否遍历过，新建一个备份的onforkstate，用size的大小查看是否访问过
            if(my_current_state==f)
            {
                std::vector<S2EExecutionState *> temp1;
                temp1=fork_condition_class[record_call_pc][conditionPC];
                if(temp1.size()!=0)
                {
                    temp1.clear();
                    return_s=s;
                     getDebugStream() << "select state: " << hexval(return_s->getID())  "\n";
                    return *return_s;
                }
                else{
                    return_s=DFS(my_current_state,conditionPC);
                    getDebugStream() << "select state: " << hexval(return_s->getID())  "\n";
                     return *return_s;
                }
                
                
            }
            else if(my_current_state==s)
            {
                std::vector<S2EExecutionState *> temp1;
                temp1=fork_condition_class[record_call_pc][conditionPC];//map是从小到大的有序map
                if(temp1.size()!=0)
                {
                    temp1.clear();
                    return_s=f;
                    return *return_s;
                }
                else{
                        return DFS(my_current_state,conditionPC);
                }
            }
        }
        else{
                getWarningsStream() << "ERROR Happened: "  << "\n";
        }
                       
    }
   
     return *return_s;
}
klee::ExecutionState &MyMultiSearcher::DFS(S2EExecutionState * state,uint32_t conditionPC)
{
    //conditionPC是fork出来state的condition的地址，现在的任务是遍历map去寻找出是谁fork出来了现在condition
    //
    //
    std::map<uint32_t,std::vector<S2EExecutionState *>>::iterator it;
    S2EExecutionState *return_s=nullptr;
    for(it=fork_condition_class_copy[record_call_pc].begin();it!=fork_condition_class_copy[record_call_pc].end();it++)
    {
        std::vector<S2EExecutionState *> temp;
        temp=it->second;
        S2EExecutionState *f,*s;
        f=temp[0];
        s=temp[1];
        uint32_t PC1,PC2;
        PC1=f->regs()->getPc();
        PC2=s->regs()->getPc();
        uint32_t temp_con_PC=it->first;
        if(PC1==conditionPC)
        {
            std::vector<S2EExecutionState *> temp1;
            temp1=fork_condition_class_copy[record_call_pc][temp_con_PC];
            if(temp.size()!=0){
                temp.clear();
                return_s=s;
                return *return_s;
            }
            else
                conditionPC=temp_con_PC;
        }
        else if(PC2==conditionPC)
        {
            std::vector<S2EExecutionState *> temp1;
            temp1=fork_condition_class_copy[record_call_pc][temp_con_PC];
            if(temp.size()!=0){
                temp.clear();
                return_s=f;
                return *return_s;
            }
            else
                conditionPC=temp_con_PC;

        }   
    }
      return *return_s;
}


void MyMultiSearcher::onARMFunctionCall(S2EExecutionState *state, uint32_t caller_pc, uint64_t function_hash) {
    //DECLARE_PLUGINSTATE(MyMultiSearcherState, state);
    record_call_pc=caller_pc;
    //-------------------
 
}

void MyMultiSearcher::onARMFunctionReturn(S2EExecutionState *state, uint32_t return_pc) {
   // DECLARE_PLUGINSTATE(MyMultiSearcherState, state);
    my_current_state=state;//赋值全局变量作为return时候的state



    // if(return_pc==exit_pc){ trace里面invalid里面加
    //  g_s2e->getCorePlugin()->onEngineShutdown.emit();
    // g_s2e->flushOutputStreams();
    // exit(0);
    // }
   
   //stateSwitchCallback(); 
   //select sgt return的时候调用selectstate
   //state=selectstate();
   s2e()->getExecutor()->MystateSwitchCallback(state); 
   s2e()->getExecutor()->setCpuExitRequest(); 
}


void MyMultiSearcher::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                                     const std::vector<klee::ref<klee::Expr>> &newConditions) {
    //DECLARE_PLUGINSTATE(MyMultiSearcherState, state);
   // std::map<uint32_t, AllKnowledgeBaseMap> cachefork_phs;
    //cachefork_phs.clear();
   
    //前面是fork 的PC，后面是state1和state2，查的时候for循环map里面的pair的first和second，
    //update的时候add记录里面都有什么state，去掉current和removed
    //newstates里面有两个S2EExecutionState，存放在map<pc,state>里面
    S2EExecutionState *first,*second;
    first=newStates[0];
    second=newStates[1];
    
    uint32_t PC;
    PC=state->regs()->getPc();
    fork_condition_class[record_call_pc][PC].push_back(first);
   fork_condition_class[record_call_pc][PC].push_back(second);
    fork_condition_class_copy[record_call_pc][PC].push_back(first);
    fork_condition_class_copy[record_call_pc][PC].push_back(second);
   
}



} // namespace plugins
} // namespace s2e
