with open("static/assets/index-6WLwG8wz.js", "r", encoding="utf-8") as f:
    content = f.read()

target = 'g.jsxs("form",{onSubmit:N.handleSubmit(M),className:"space-y-4",children:[g.jsxs("div",{className:"grid grid-cols-1 md:grid-cols-2 gap-4",children:[g.jsx(ar,{control:N.control,name:"categoryId",render:({field:U})=>g.jsxs(er,{children:[g.jsx(tr,{children:"Category"}),g.jsxs(fs,{onValueChange:D=>U.onChange(Number(D)),value:U.value?U.value.toString():void 0,children:[g.jsx(rr,{children:g.jsx(Wo,{children:g.jsx(ds,{placeholder:"Select category"})})}),g.jsx(Go,{children:y?.map(D=>g.jsx(yn,{value:D.id.toString(),children:D.name},D.id))})]}),g.jsx(or,{})]})}),g.jsx(ar,{control:N.control,name:"departmentId",render:({field:U})=>g.jsxs(er,{children:[g.jsx(tr,{children:"Department"}),g.jsxs(fs,{onValueChange:D=>U.onChange(Number(D)),value:U.value?U.value.toString():void 0,children:[g.jsx(rr,{children:g.jsx(Wo,{children:g.jsx(ds,{placeholder:"Select department"})})}),g.jsx(Go,{children:depts?.map(D=>g.jsx(yn,{value:D.id.toString(),children:D.name},D.id))})]}),g.jsx(or,{})]})})]})'
# Wait! In update_js_bundle_v2, did it set the onValueChange function to use setValue?
# Let's check target: in update_js_bundle_v2, the replacement for target 5 was:
# 'g.jsxs("form",{onSubmit:N.handleSubmit(M),className:"space-y-4",children:[g.jsxs("div",{className:"grid grid-cols-1 md:grid-cols-2 gap-4",children:[g.jsx(ar,{control:N.control,name:"categoryId",render:({field:U})=>g.jsxs(er,{children:[g.jsx(tr,{children:"Category"}),g.jsxs(fs,{onValueChange:D=>{U.onChange(Number(D));const catName=y?.find(x=>x.id===Number(D))?.name;if(catName)N.setValue("name",catName);},value:U.value?U.value.toString():void 0,children:[g.jsx(rr,{children:g.jsx(Wo,{children:g.jsx(ds,{placeholder:"Select category"})})}),g.jsx(Go,{children:y?.map(D=>g.jsx(yn,{value:D.id.toString(),children:D.name},D.id))})]}),g.jsx(or,{})]})}),g.jsx(ar,{control:N.control,name:"departmentId",render:({field:U})=>g.jsxs(er,{children:[g.jsx(tr,{children:"Department"}),g.jsxs(fs,{onValueChange:D=>U.onChange(Number(D)),value:U.value?U.value.toString():void 0,children:[g.jsx(rr,{children:g.jsx(Wo,{children:g.jsx(ds,{placeholder:"Select department"})})}),g.jsx(Go,{children:depts?.map(D=>g.jsx(yn,{value:D.id.toString(),children:D.name},D.id))})]}),g.jsx(or,{})]})})]})'
# Yes, that is the exact target string we checked in verify_exact_matches_v3!

replacement = 'g.jsxs("form",{onSubmit:N.handleSubmit(M),className:"space-y-4",children:[g.jsx(ar,{control:N.control,name:"name",render:({field:U})=>g.jsx("input",{type:"hidden",...U})}),g.jsxs("div",{className:"grid grid-cols-1 md:grid-cols-2 gap-4",children:[g.jsx(ar,{control:N.control,name:"categoryId",render:({field:U})=>g.jsxs(er,{children:[g.jsx(tr,{children:"Category"}),g.jsxs(fs,{onValueChange:D=>{U.onChange(Number(D));const catName=y?.find(x=>x.id===Number(D))?.name;if(catName)N.setValue("name",catName);},value:U.value?U.value.toString():void 0,children:[g.jsx(rr,{children:g.jsx(Wo,{children:g.jsx(ds,{placeholder:"Select category"})})}),g.jsx(Go,{children:y?.map(D=>g.jsx(yn,{value:D.id.toString(),children:D.name},D.id))})]}),g.jsx(or,{})]})}),g.jsx(ar,{control:N.control,name:"departmentId",render:({field:U})=>g.jsxs(er,{children:[g.jsx(tr,{children:"Department"}),g.jsxs(fs,{onValueChange:D=>U.onChange(Number(D)),value:U.value?U.value.toString():void 0,children:[g.jsx(rr,{children:g.jsx(Wo,{children:g.jsx(ds,{placeholder:"Select department"})})}),g.jsx(Go,{children:depts?.map(D=>g.jsx(yn,{value:D.id.toString(),children:D.name},D.id))})]}),g.jsx(or,{})]})})]})'

count = content.count(target)
if count == 1:
    content = content.replace(target, replacement)
    print("Successfully replaced.")
else:
    print(f"Error: target occurs {count} times.")
    exit(1)

with open("static/assets/index-6WLwG8wz.js", "w", encoding="utf-8") as f:
    f.write(content)
