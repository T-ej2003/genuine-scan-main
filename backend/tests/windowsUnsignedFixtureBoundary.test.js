const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const JSZip=require('jszip');
(async()=>{
  const packaging=path.resolve(__dirname,'../local-print-agent/packaging');
  const source=fs.readFileSync(path.join(packaging,'build-connector-release.mjs'),'utf8');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-inspection-'));
  try {
    const releaseRoot=path.join(root,'releases'),staging=path.join(root,'.connector-build');fs.mkdirSync(staging);
    const binary=path.join(root,'synthetic.exe');fs.writeFileSync(binary,'non-executable synthetic inspection bytes');
    // Load actual production packaging functions; native toolchains and signing
    // are not invoked. File copies, ZIP construction and manifest writes are real.
    const names=['writeAsciiFile','readWindowsAssetTemplate','sha256ForFile','addDirectoryToZip','archiveDirectory','buildWindowsPackage','updateManifest'];
    const declarations=names.map(name=>{const match=source.match(new RegExp('^const '+name+' = [\\s\\S]*?(?=^const |^main\\(|$(?![\\s\\S]))','m'));assert(match,`missing ${name}`);return match[0];}).join('\n');
    const context={fs,path,crypto,JSZip,console,releaseRoot,version:'2026.10.29.1',publishedAt:new Date().toISOString(),requiredProtocolVersion:'local-agent-direct-v2',minimumBuildVersion:'2026.10.29.1',transportDiagnosticsVersion:'fixture',connectorCapabilities:{},webAppBaseUrl:'https://isolated.example.invalid',windowsInstallAssetRoot:path.resolve(__dirname,'../local-print-agent/install/windows'),ensureDir:dir=>fs.mkdirSync(dir,{recursive:true})};
    vm.runInNewContext(declarations+'\nglobalThis.build=buildWindowsPackage;globalThis.update=updateManifest;',context);
    const zipPath=await context.build({winX64:binary},staging);
    assert.equal(path.dirname(zipPath),staging);assert.match(path.basename(zipPath),/INSPECTION-ONLY/);
    assert.equal(fs.existsSync(releaseRoot),false,'unsigned output must stay outside publication directories');
    const zip=await JSZip.loadAsync(fs.readFileSync(zipPath));const readme=await zip.file('README.txt').async('string');
    assert.match(readme,/NON-INSTALLABLE INSPECTION FIXTURE/);assert.match(readme,/Do not run/);assert.doesNotMatch(readme,/Run Install Connector.cmd/);
    assert.match(await zip.file('Install Connector.cmd').async('string'),/-ExecutionPolicy AllSigned -File/);
    assert.equal(context.update({publishable:false}),false);assert.equal(fs.existsSync(releaseRoot),false);
    fs.mkdirSync(releaseRoot);const manifest=path.join(releaseRoot,'manifest.json');
    const trusted={trustLevel:'trusted',signatureStatus:'signed',relativePath:'approved-signed.exe',sha256:'synthetic-existing-record'};
    fs.writeFileSync(manifest,JSON.stringify({latestVersion:context.version,releases:[{version:context.version,platforms:{windows:trusted}}]}));
    const before=fs.readFileSync(manifest,'utf8');assert.equal(context.update({publishable:false}),false);assert.equal(fs.readFileSync(manifest,'utf8'),before);
    const pkg=path.join(staging,'synthetic.pkg');fs.writeFileSync(pkg,'synthetic Mac artifact; no signing performed');
    assert.equal(context.update({publishable:true,pkgPath:pkg}),true);
    assert.deepEqual(JSON.parse(fs.readFileSync(manifest)).releases[0].platforms.windows,trusted,'macOS metadata refresh must preserve the existing governed Windows record');
    fs.writeFileSync(manifest,JSON.stringify({releases:[{version:context.version,platforms:{windows:{trustLevel:'unsigned',signatureStatus:'unsigned'}}}]}));
    context.update({publishable:true,pkgPath:pkg});assert.equal(JSON.parse(fs.readFileSync(manifest)).releases[0].platforms.windows,undefined);
    for(const name of ['WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH','WINDOWS_CONNECTOR_UNSIGNED_INSTALLER_PATH']){
      const result=spawnSync(process.execPath,[path.join(packaging,'build-connector-release.mjs')],{cwd:root,encoding:'utf8',env:{...process.env,WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH:'',WINDOWS_CONNECTOR_UNSIGNED_INSTALLER_PATH:'',[name]:binary}});
      assert.notEqual(result.status,0);assert.match(result.stderr,/governed signed Windows workflow/);
    }
    const result=spawnSync(process.execPath,[path.join(packaging,'publish-windows-connector-zip-release.mjs')],{cwd:root,encoding:'utf8'});
    assert.notEqual(result.status,0);assert.match(result.stderr,/Unsigned Windows ZIP publication is retired/);
    console.log('PASS unsigned Windows inspection: actual ZIP outside releases, non-runnable instructions, AllSigned retained, manifest isolation, trusted metadata preservation, retired publication/overrides');
  } finally {
    assert(path.resolve(root).startsWith(path.resolve(os.tmpdir())+path.sep));fs.rmSync(root,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
