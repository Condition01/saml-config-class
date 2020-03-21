/*
 * Copyright 2020 Vincenzo De Notaris
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */
package br.com.saintgobain.authsaml2.config

import br.com.saintgobain.authsaml2.core.SAMLUserDetailsServiceImpl
import org.apache.bcel.util.ClassPath
import org.apache.commons.httpclient.HttpClient
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager
import org.apache.velocity.app.VelocityEngine
import org.opensaml.saml2.core.NameID
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider
import org.opensaml.saml2.metadata.provider.MetadataProvider
import org.opensaml.saml2.metadata.provider.MetadataProviderException
import org.opensaml.xml.parse.ParserPool
import org.opensaml.xml.parse.StaticBasicParserPool
import org.springframework.beans.factory.DisposableBean
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.saml.*
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.springframework.security.saml.key.JKSKeyManager
import org.springframework.security.saml.key.KeyManager
import org.springframework.security.saml.log.SAMLDefaultLogger
import org.springframework.security.saml.metadata.*
import org.springframework.security.saml.parser.ParserPoolHolder
import org.springframework.security.saml.processor.*
import org.springframework.security.saml.util.VelocityFactory
import org.springframework.security.saml.websso.*
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.channel.ChannelProcessingFilter
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.csrf.CsrfFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.util.ResourceUtils
import java.io.File
import java.util.*

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
class WebSecurityConfig : WebSecurityConfigurerAdapter(), InitializingBean, DisposableBean {
    private var backgroundTaskTimer: Timer? = null
    private var multiThreadedHttpConnectionManager: MultiThreadedHttpConnectionManager? = null
    fun init() {
        backgroundTaskTimer = Timer(true)
        multiThreadedHttpConnectionManager = MultiThreadedHttpConnectionManager()
    }

    fun shutdown() {
        backgroundTaskTimer!!.purge()
        backgroundTaskTimer!!.cancel()
        multiThreadedHttpConnectionManager!!.shutdown()
    }

    @Autowired
    lateinit var samlUserDetailsServiceImpl: SAMLUserDetailsServiceImpl

    // Initialization of the velocity engine
    @Bean
    fun velocityEngine(): VelocityEngine {
        return VelocityFactory.getEngine()
    }

    // XML parser pool needed for OpenSAML parsing
    @Bean(initMethod = "initialize")
    fun parserPool(): StaticBasicParserPool {
        return StaticBasicParserPool()
    }

    @Bean(name = ["parserPoolHolder"])
    fun parserPoolHolder(): ParserPoolHolder {
        return ParserPoolHolder()
    }

    // Bindings, encoders and decoders used for creating and parsing messages
    @Bean
    fun httpClient(): HttpClient {
        return HttpClient(multiThreadedHttpConnectionManager)
    }

    // SAML Authentication Provider responsible for validating of received SAML
// messages
    @Bean
    fun samlAuthenticationProvider(): SAMLAuthenticationProvider {
        val samlAuthenticationProvider = SAMLAuthenticationProvider()
        samlAuthenticationProvider.userDetails = samlUserDetailsServiceImpl
        samlAuthenticationProvider.isForcePrincipalAsString = false
        return samlAuthenticationProvider
    }

    // Provider of default SAML Context
    @Bean
    fun contextProvider(): SAMLContextProviderImpl {
        return SAMLContextProviderImpl()
    }

    // Logger for SAML messages and events
    @Bean
    fun samlLogger(): SAMLDefaultLogger {
        return SAMLDefaultLogger()
    }

    // SAML 2.0 WebSSO Assertion Consumer
    @Bean
    fun webSSOprofileConsumer(): WebSSOProfileConsumer {
        return WebSSOProfileConsumerImpl()
    }

    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
    @Bean
    fun hokWebSSOprofileConsumer(): WebSSOProfileConsumerHoKImpl {
        return WebSSOProfileConsumerHoKImpl()
    }

    // SAML 2.0 Web SSO profile --> trata os requests e responses
    @Bean
    fun webSSOprofile(): WebSSOProfile {
        return WebSSOProfileImpl()
    }

    // SAML 2.0 Holder-of-Key Web SSO profile -->  processa as responses
    @Bean
    fun hokWebSSOProfile(): WebSSOProfileConsumerHoKImpl {
        return WebSSOProfileConsumerHoKImpl()
    }

    // SAML 2.0 ECP profile -->
    @Bean
    fun ecpprofile(): WebSSOProfileECPImpl {
        return WebSSOProfileECPImpl()
    }

    @Bean
    fun logoutprofile(): SingleLogoutProfile {
        return SingleLogoutProfileImpl()
    }

    // Central storage of cryptographic keys --> Bean que lida com as keys
    @Bean
    fun keyManager(): KeyManager {
        val loader = DefaultResourceLoader()
        val storeFile = loader
                .getResource("classpath:/saml/tekbkey.jks")
        val storePass = "tekbondAa@"
        val passwords: MutableMap<String, String> = HashMap()
        passwords["tekbond.com.br"] = storePass
        val defaultKey = "tekbond.com.br"
        return JKSKeyManager(storeFile, storePass, passwords, defaultKey)
    }

    @Bean
    fun defaultWebSSOProfileOptions(): WebSSOProfileOptions {
        val webSSOProfileOptions = WebSSOProfileOptions()
        webSSOProfileOptions.isIncludeScoping = false
        webSSOProfileOptions.binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        return webSSOProfileOptions
    }

    // Entry point to initialize authentication, default values taken from
    // properties file
    @Bean
    fun samlEntryPoint(): SAMLEntryPoint {
        val samlEntryPoint = SAMLEntryPoint()
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions())
        return samlEntryPoint
    }

    // Setup advanced info about metadata -- Algumas configuraçoes avançadas em relaçao a metadata
    @Bean
    fun extendedMetadata(): ExtendedMetadata {
        val extendedMetadata = ExtendedMetadata()
        extendedMetadata.isIdpDiscoveryEnabled = true
        extendedMetadata.signingAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        extendedMetadata.isSignMetadata = true
        extendedMetadata.isEcpEnabled = true
        return extendedMetadata
    }

    // IDP Discovery Service
    @Bean
    fun samlIDPDiscovery(): SAMLDiscovery {
        val idpDiscovery = SAMLDiscovery()
        idpDiscovery.idpSelectionPath = "/saml/discovery"
        return idpDiscovery
    }

//    Aqui voce configura um idp para utilizar
//    @Bean
//    @Qualifier("spring.security.saml.idp.id")
//    @Throws(MetadataProviderException::class)
//    fun testIdpMetadata(): ExtendedMetadataDelegate {
//        val idpTesteMetadata = "http://localhost:8081/sample-idp/saml/idp/metadata"
//        val httpMetadataProvider = HTTPMetadataProvider(
//                backgroundTaskTimer, httpClient(), idpTesteMetadata)
//        httpMetadataProvider.parserPool = parserPool()
//        val extendedMetadataDelegate = ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadata())
//        extendedMetadataDelegate.isMetadataTrustCheck = false
//        extendedMetadataDelegate.isMetadataRequireSignature = false
//        backgroundTaskTimer!!.purge()
//        return extendedMetadataDelegate
//    }

    @Bean
    @Qualifier("spring.security.saml.idp.id")
    @Throws(MetadataProviderException::class)
    fun idpTesteFileBasedMetadata() : ExtendedMetadataDelegate{
        val loader = DefaultResourceLoader()
        val storeFile = loader
                .getResource("classpath:/saml/saml-idp-metadata.xml")
        val idpFileSystemMetadataProvider = FilesystemMetadataProvider(storeFile.file)
        idpFileSystemMetadataProvider.parserPool = parserPool()
        val extendedMetadataDelegate = ExtendedMetadataDelegate(idpFileSystemMetadataProvider, extendedMetadata())
        extendedMetadataDelegate.isMetadataTrustCheck = false
        extendedMetadataDelegate.isMetadataRequireSignature = false
        backgroundTaskTimer!!.purge()
        return extendedMetadataDelegate
    }



    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // is here
    // Do no forget to call iniitalize method on providers
    @Bean
    @Qualifier("metadata")
    @Throws(MetadataProviderException::class)
    fun metadata(): CachingMetadataManager {
        val providers: MutableList<MetadataProvider> = ArrayList()
        providers.add(idpTesteFileBasedMetadata())
        return CachingMetadataManager(providers)
    }

    @Bean
    fun metadataGenerator(): MetadataGenerator {
        val metadataGenerator = MetadataGenerator()

        metadataGenerator.id = "SPM58b7b185-7686-4205-8b8a-2175e6018428"
        metadataGenerator.entityId = "uat-company.eastus2.cloudapp.azure.com/"
        metadataGenerator.nameID = mutableListOf("EMAIL", "TRANSIENT", "PERSISTENT", "UNSPECIFIED", "X509_SUBJECT")
        metadataGenerator.extendedMetadata = extendedMetadata() //pega da config local acima
        metadataGenerator.isIncludeDiscoveryExtension = false
        metadataGenerator.setKeyManager(keyManager())
//        metadataGenerator.bindingsSSO = listOf("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
        return metadataGenerator
    }

    // The filter is waiting for connections on URL suffixed with filterSuffix
    // and presents SP metadata there
    // Coloca o prefixo /saml/metadata na URL
    @Bean
    fun metadataDisplayFilter(): MetadataDisplayFilter {
        return MetadataDisplayFilter()
    }

    // Configuraçao para login com sucesso
    @Bean
    fun successRedirectHandler(): SavedRequestAwareAuthenticationSuccessHandler {
        val successRedirectHandler = SavedRequestAwareAuthenticationSuccessHandler()
        successRedirectHandler.setDefaultTargetUrl("/landing")
        return successRedirectHandler
    }

    // Configuraçao para falha de login
    @Bean
    fun authenticationFailureHandler(): SimpleUrlAuthenticationFailureHandler {
        val failureHandler = SimpleUrlAuthenticationFailureHandler()
        failureHandler.setUseForward(true)
        failureHandler.setDefaultFailureUrl("/error")
        return failureHandler
    }

    // Processa as mensagens enviadas do IDP como parte do perfil do detentor da chave do WebSSO.
    @Bean
    @Throws(Exception::class)
    fun samlWebSSOHoKProcessingFilter(): SAMLWebSSOHoKProcessingFilter {
        val samlWebSSOHoKProcessingFilter = SAMLWebSSOHoKProcessingFilter()
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler())
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager())
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler())
        return samlWebSSOHoKProcessingFilter
    }

    // Processing filter for WebSSO profile messages
    // processa a chegada de mensagens SAML delegando ao WebSSOProfile.
    // Após a obtenção do SAMLAuthenticationToken, os provedores de autenticação
    // são solicitados a autenticá-lo.
    @Bean
    @Throws(Exception::class)
    fun samlWebSSOProcessingFilter(): SAMLProcessingFilter {
        val samlWebSSOProcessingFilter = SAMLProcessingFilter()
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager())
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler())
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler())
        return samlWebSSOProcessingFilter
    }


    @Bean
    fun metadataGeneratorFilter(): MetadataGeneratorFilter {
        return MetadataGeneratorFilter(metadataGenerator())
    }

    // Handler for successful logout
    @Bean
    fun successLogoutHandler(): SimpleUrlLogoutSuccessHandler {
        val successLogoutHandler = SimpleUrlLogoutSuccessHandler()
        successLogoutHandler.setDefaultTargetUrl("/")
        return successLogoutHandler
    }

    // Logout handler terminating local session
    @Bean
    fun logoutHandler(): SecurityContextLogoutHandler {
        val logoutHandler = SecurityContextLogoutHandler()
        logoutHandler.isInvalidateHttpSession = true
        logoutHandler.setClearAuthentication(true)
        return logoutHandler
    }

    // Filter processing incoming logout messages
    // First argument determines URL user will be redirected to after successful
    // global logout
    @Bean
    fun samlLogoutProcessingFilter(): SAMLLogoutProcessingFilter {
        return SAMLLogoutProcessingFilter(successLogoutHandler(),
                logoutHandler())
    }

    // Overrides default logout processing filter with the one processing SAML
    // messages
    @Bean
    fun samlLogoutFilter(): SAMLLogoutFilter {
        return SAMLLogoutFilter(successLogoutHandler(), arrayOf<LogoutHandler>(logoutHandler()), arrayOf<LogoutHandler>(logoutHandler()))
    }

    // Bindings
    private fun artifactResolutionProfile(): ArtifactResolutionProfile {
        val artifactResolutionProfile = ArtifactResolutionProfileImpl(httpClient())
        artifactResolutionProfile.setProcessor(SAMLProcessorImpl(soapBinding()))
        return artifactResolutionProfile
    }

    @Bean
    fun artifactBinding(parserPool: ParserPool?, velocityEngine: VelocityEngine?): HTTPArtifactBinding {
        return HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile())
    }

    @Bean
    fun soapBinding(): HTTPSOAP11Binding {
        return HTTPSOAP11Binding(parserPool())
    }

    @Bean
    fun httpPostBinding(): HTTPPostBinding {
        return HTTPPostBinding(parserPool(), velocityEngine())
    }

    @Bean
    fun httpRedirectDeflateBinding(): HTTPRedirectDeflateBinding {
        return HTTPRedirectDeflateBinding(parserPool())
    }

    @Bean
    fun httpSOAP11Binding(): HTTPSOAP11Binding {
        return HTTPSOAP11Binding(parserPool())
    }

    @Bean
    fun httpPAOS11Binding(): HTTPPAOS11Binding {
        return HTTPPAOS11Binding(parserPool())
    }


    // Processor


    @Bean
    fun processor(): SAMLProcessorImpl {
        val bindings: MutableCollection<SAMLBinding> = ArrayList()
        bindings.add(httpRedirectDeflateBinding())
        bindings.add(httpPostBinding())
//        bindings.add(artifactBinding(parserPool(), velocityEngine()))
//        bindings.add(httpSOAP11Binding())
//        bindings.add(httpPAOS11Binding())
        return SAMLProcessorImpl(bindings)
    }

    /**
     * Define the security filter chain in order to support SSO Auth by using SAML 2.0
     *
     * @return Filter chain proxy
     * @throws Exception
     */

    //Nesse metodo eu seto todos os filtros necessarios para o funcionamento
    @Bean
    @Throws(Exception::class)
    fun samlFilter(): FilterChainProxy {
        val chains: MutableList<SecurityFilterChain> = ArrayList()
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/login/**"),
                samlEntryPoint()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/logout/**"),
                samlLogoutFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/metadata/**"),
                metadataDisplayFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/SSOHoK/**"),
                samlWebSSOHoKProcessingFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter()))
        chains.add(DefaultSecurityFilterChain(AntPathRequestMatcher("/saml/discovery/**"),
                samlIDPDiscovery()))
        return FilterChainProxy(chains)
    }

    /**
     * Returns the authentication manager currently used by Spring.
     * It represents a bean definition with the aim allow wiring from
     * other classes performing the Inversion of Control (IoC).
     *
     * @throws  Exception
     */
    @Bean
    @Throws(Exception::class)
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }

    /**
     * Defines the web based security configuration.
     *
     * @param   http It allows configuring web based security for specific http requests.
     * @throws  Exception
     */
    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http
//                .cors().disable()
                .httpBasic()
                .authenticationEntryPoint(samlEntryPoint())
        http
                .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter::class.java)
                .addFilterAfter(samlFilter(), BasicAuthenticationFilter::class.java)
                .addFilterBefore(samlFilter(), CsrfFilter::class.java)
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/saml/**").permitAll()
                .antMatchers("/css/**").permitAll()
                .antMatchers("/img/**").permitAll()
                .antMatchers("/js/**").permitAll()
                .anyRequest().authenticated()
        http
                .logout()
                .disable() // The logout procedure is already handled by SAML filters.
    }

    /**
     * Sets a custom authentication provider.
     *
     * @param   auth SecurityBuilder used to create an AuthenticationManager.
     * @throws  Exception
     */
    @Throws(Exception::class)
    override fun configure(auth: AuthenticationManagerBuilder) {
        auth
                .authenticationProvider(samlAuthenticationProvider())
    }

    @Throws(Exception::class)
    override fun afterPropertiesSet() {
        init()
    }

    @Throws(Exception::class)
    override fun destroy() {
        shutdown()
    }

    companion object {
        // Initialization of OpenSAML library
        @Bean
        fun sAMLBootstrap(): SAMLBootstrap {
            return SAMLBootstrap()
        }
    }
}
