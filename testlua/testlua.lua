
function ProcFilterEvent(e)
  procfilter.Log("Entering event handler")
  if e.dwEventId == procfilter.PROCFILTER_EVENT_INIT then
    procfilter.RegisterPlugin("1.0.0-beta.2", "luatest", 0, 0, true, procfilter.PROCFILTER_EVENT_PROCESS_CREATE, procfilter.PROCFILTER_EVENT_NONE)
  elseif e.dwEventId == procfilter.PROCFILTER_EVENT_PROCESS_CREATE then
    -- This fails; the file name is Unicode and Lua strings are ASCII.
    -- SWIG doesn't support this by default so it'll have to be added later.
    --procfilter.Log("Process created: " .. e.lpszFileName)
  end

  return procfilter.PROCFILTER_RESULT_NONE
end