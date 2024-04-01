GH_RAW_BASE="https://raw.githubusercontent.com"


## Gather wallbox and modify
path="custom_components/wallbox/wallbox"
rm ${path}/*.py

GH_ACCOUNT="tmenguy"
GH_REPO="wallbox"
GH_BRANCH="master"
gh_path="${GH_RAW_BASE}/${GH_ACCOUNT}/${GH_REPO}/${GH_BRANCH}/wallbox"
files="__init__.py bearerauth.py statuses.py wallbox.py"

for file in ${files}; do
  wget ${gh_path}/${file} -O ${path}/${file}
  gsed -i 's/from wallbox /from \. /g' ${path}/${file}
  gsed -i 's/from wallbox/from \./g' ${path}/${file}
  gsed -i 's/from \.\./from \./g' ${path}/${file}
done
