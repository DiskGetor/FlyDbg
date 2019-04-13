-- premake5.lua
workspace "FlyDbg"
  startproject "FlyDbg"
  platforms { "Win32", "Win64" }
  configurations { "Debug", "Release" }

IncludeDir = {}
IncludeDir["Zydis"] = "deps/zydis/include"
IncludeDir["Zycore"] = "deps/zycore/include"

project "FlyDbg"
  kind "ConsoleApp"
  language "C++"
  targetdir "bin/%{cfg.buildcfg}-%{cfg.architecture}"
  targetname "%{prj.name}_%{cfg.architecture}"

	pchheader "pch.h"
	pchsource "src/pch.cpp"

  defines {
    "ZYDIS_EXPORT="
  }

  files {
    "src/**.h",
    "src/**.cpp"
  }

  libdirs {
    "libs"
  }

  links {
    "Zydis_%{cfg.architecture}.lib"
  }

  includedirs {
    "src",
		"%{IncludeDir.Zydis}",
    "%{IncludeDir.Zycore}"
  }

  linkoptions {
    "/NODEFAULTLIB:\"MSVCRT\""
  }

  filter { "system:windows", "action:vs*" }
    systemversion "latest"

  filter { "platforms:Win32" }
    system "Windows"
    architecture "x32"

  filter { "platforms:Win64" }
    system "Windows"
    architecture "x64"

  filter "configurations:Debug*"
    defines { "DEBUG" }
    symbols "On"

  filter "configurations:Release*"
    defines { "NDEBUG" }
    optimize "On"
