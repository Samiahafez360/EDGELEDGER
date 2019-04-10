file(REMOVE_RECURSE
  "MyExe1.pdb"
  "MyExe1"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/MyExe1.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
