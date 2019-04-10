file(REMOVE_RECURSE
  "MyExe2.pdb"
  "MyExe2"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/MyExe2.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
