///
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>

#include "LuaExpression.h"
#include "LuaS2EExecutionState.h"
#include "LuaS2EExecutionStateMemory.h"
#include "LuaS2EExecutionStateRegisters.h"

namespace s2e {
namespace plugins {

const char LuaS2EExecutionState::className[] = "LuaS2EExecutionState";

Lunar<LuaS2EExecutionState>::RegType LuaS2EExecutionState::methods[] = {
    LUNAR_DECLARE_METHOD(LuaS2EExecutionState, mem),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionState, regs),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionState, createSymbolicValue),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionState, kill),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionState, setPluginProperty),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionState, getPluginProperty),
    LUNAR_DECLARE_METHOD(LuaS2EExecutionState, debug),
    {0, 0}};

int LuaS2EExecutionState::mem(lua_State *L) {
    Lunar<LuaS2EExecutionStateMemory>::push(L, &m_memory);
    return 1;
}

int LuaS2EExecutionState::regs(lua_State *L) {
    Lunar<LuaS2EExecutionStateRegisters>::push(L, &m_registers);
    return 1;
}

int LuaS2EExecutionState::createSymbolicValue(lua_State *L) {
    std::string name = luaL_checkstring(L, 1);
    long size = (long) luaL_checkinteger(L, 2);

    assert(size <= 8);

    std::vector<uint8_t> buffer(size);
    for (unsigned i = 0; i < size; ++i) {
        buffer[i] = 0;
    }

    klee::ref<klee::Expr> value = m_state->createSymbolicValue(name, size * 8, buffer);
    g_s2e->getDebugStream(m_state) << "LuaS2EExecutionState: " << value << "\n";

    // lua will manage the LuaExpression** ptr
    LuaExpression **c = static_cast<LuaExpression **>(lua_newuserdata(L, sizeof(LuaExpression *)));
    *c = new LuaExpression(value); // we manage this
    luaL_getmetatable(L, "LuaExpression");
    lua_setmetatable(L, -2);
    return 1;
}

int LuaS2EExecutionState::kill(lua_State *L) {
    long status = (long) luaL_checkinteger(L, 1);
    std::string message = luaL_checkstring(L, 2);

    std::stringstream ss;
    ss << "LuaS2EExecutionState: killed status:" << status << " message:" << message;
    g_s2e->getExecutor()->terminateState(*m_state, ss.str());

    return 0;
}

int LuaS2EExecutionState::getPluginProperty(lua_State *L) {
    std::string pluginName = luaL_checkstring(L, 1);
    std::string property = luaL_checkstring(L, 2);
    std::string value;

    Plugin *plugin = g_s2e->getPlugin(pluginName);
    if (!plugin) {
        g_s2e->getWarningsStream(m_state) << "BaseInstructions plugin not loaded\n";
        goto err;
    }

    if (!plugin->getProperty(m_state, property, value)) {
        goto err;
    }

    lua_pushstring(L, value.c_str());

    return 1;

err:
    return 0;
}

int LuaS2EExecutionState::setPluginProperty(lua_State *L) {
    std::string pluginName = luaL_checkstring(L, 1);
    std::string property = luaL_checkstring(L, 2);
    std::string value = luaL_checkstring(L, 3);
    bool ret = false;
    Plugin *plugin = g_s2e->getPlugin(pluginName);
    if (!plugin) {
        g_s2e->getWarningsStream(m_state) << "BaseInstructions plugin not loaded\n";
        goto err;
    }

    ret = plugin->setProperty(m_state, property, value);

err:
    lua_pushboolean(L, ret);
    return 1;
}

int LuaS2EExecutionState::debug(lua_State *L) {
    std::string str = luaL_checkstring(L, 1);
    char c = 0;

    if (str[str.length() - 1] != '\n') {
        c = '\n';
    }

    g_s2e->getDebugStream(m_state) << str << c;

    return 0;
}
}
}
