#[cfg(feature = "serde")]
extern crate serde;

mod tests {
    use anoncreds_clsignatures::*;

    #[test]
    fn credential_with_negative_attribute_and_empty_proof_works() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_dec_known("height", "-1")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        )
        .unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        )
        .unwrap();

        let sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &cred_values,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    #[test]
    fn multiple_predicates() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder
            .add_attr("funds_sold_and_securities_purchased")
            .unwrap();
        credential_schema_builder
            .add_attr("other_earning_assets")
            .unwrap();
        credential_schema_builder.add_attr("cash").unwrap();
        credential_schema_builder.add_attr("allowance").unwrap();
        credential_schema_builder.add_attr("total_assets").unwrap();
        credential_schema_builder
            .add_attr("domestic_interest_bearing_deposits")
            .unwrap();
        credential_schema_builder
            .add_attr("funds_purchased")
            .unwrap();
        credential_schema_builder
            .add_attr("long_term_debt")
            .unwrap();
        credential_schema_builder
            .add_attr("non_interest_bearing_liabilities")
            .unwrap();
        credential_schema_builder
            .add_attr("shareholder_equity")
            .unwrap();
        credential_schema_builder
            .add_attr("total_liabilities")
            .unwrap();

        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();
        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_value_hidden("master_secret", &master_secret.value().unwrap())
            .unwrap();
        credential_values_builder
            .add_dec_known("funds_sold_and_securities_purchased", "50")
            .unwrap();
        credential_values_builder
            .add_dec_known("other_earning_assets", "60")
            .unwrap();
        credential_values_builder
            .add_dec_known("cash", "70")
            .unwrap();
        credential_values_builder
            .add_dec_known("allowance", "80")
            .unwrap();
        credential_values_builder
            .add_dec_known("total_assets", "260")
            .unwrap();

        credential_values_builder
            .add_dec_known("domestic_interest_bearing_deposits", "10")
            .unwrap();
        credential_values_builder
            .add_dec_known("funds_purchased", "20")
            .unwrap();
        credential_values_builder
            .add_dec_known("long_term_debt", "30")
            .unwrap();
        credential_values_builder
            .add_dec_known("non_interest_bearing_liabilities", "40")
            .unwrap();
        credential_values_builder
            .add_dec_known("shareholder_equity", "50")
            .unwrap();
        credential_values_builder
            .add_dec_known("total_liabilities", "150")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "b977afe22b5b446109797ad925d9f133fc33c1914081071295d2ac1ddce3385d",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        )
        .unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        )
        .unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder
            .add_revealed_attr("total_liabilities")
            .unwrap();

        sub_proof_request_builder
            .add_predicate("funds_sold_and_securities_purchased", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("funds_sold_and_securities_purchased", "GT", 0)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("other_earning_assets", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("cash", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("allowance", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("total_assets", "GT", 100)
            .unwrap();

        sub_proof_request_builder
            .add_predicate("domestic_interest_bearing_deposits", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("funds_purchased", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("long_term_debt", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("non_interest_bearing_liabilities", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("shareholder_equity", "LE", 100)
            .unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &cred_values,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn credential_primary_public_key_conversion_works() {
        let string1 = r#"{
                 "n":"94752773003676215520340390286428145970577435379747248974837494389412082076547661891067434652276048522392442077335235388384984508621151996372559370276527598415204914831299768834758349425880859567795461321350412568232531440683627330032285846734752711268206613305069973750567165548816744023441650243801226580089078611213688037852063937259593837571943085718154394160122127891902723469618952030300431400181642597638732611518885616750614674142486169255034160093153314427704384760404032620300207070597238445621198019686315730573836193179483581719638565112589368474184957790046080767607443902003396643479910885086397579016949",
                 "s":"69412039600361800795429063472749802282903100455399422661844374992112119187258494682747330126416608111152308407310993289705267392969490079422545377823004584691698371089275086755756916575365439635768831063415050875440259347714303092581127338698890829662982679857654396534761554232914231213603075653629534596880597317047082696083166437821687405393805812336036647064899914817619861844092002636340952247588092904075021313598848481976631171767602864723880294787434756140969093416957086578979859382777377267118038126527549503876861370823520292585383483415337137062969402135540724590433024573312636828352734474276871187481042",
                 "r":{
                    "age":"90213462228557102785520674066817329607065098280886260103565465379328385444439123494955469500769864345819799623656302322427095342533906338563811194606234218499052997878891037890681314502037670093285650999142741875494918117023196753133733183769000368858655309319559871473827485381905587653145346258174022279515774231018893119774525087260785417971477049379955435611260162822960318458092151247522911151421981946748062572207451174079699745404644326303405628719711440096340436702151418321760375229323874027809433387030362543124015034968644213166988773750220839778654632868402703075643503247560457217265822566406481434257658",
                    "height":"5391629214047043372090966654120333203094518833743674393685635640778311836867622750170495792524304436281896432811455146477306501487333852472234525296058562723428516533641819658096275918819548576029252844651857904411902677509566190811985500618327955392620642519618001469964706236997279744030829811760566269297728600224591162795849338756438466021999870256717098048301453122263380103723520670896747657149140787953289875480355961166269553534983692005983375091110745903845958291035125718192228291126861666488320123420563113398593180368102996188897121307947248313167444374640621348136184583596487812048321382789134349482978",
                    "name":"77620276231641170120118188540269028385259155493880444038204934044861538875241492581309232702380290690573764595644801264135299029620031922004969464948925209245961139274806949465303313280327009910224580146266877846633558282936147503639084871235301887617650455108586169172459479774206351621894071684884758716731250212971549835402948093455393537573942251389197338609379019568250835525301455105289583537704528678164781839386485243301381405947043141406604458853106372019953011725448481499511842635580639867624862131749700424467221215201558826025502015289693451254344465767556321748122037274143231500322140291667454975911415",
                    "sex":"9589127953934298285127566793382980040568251918610023890115614786922171891298122457059996745443282235104668609426602496632245081143706804923757991602521162900045665258654877250328921570207935035808607238170708932487500434929591458680514420504595293934408583558084774019418964434729989362874165849497341625769388145344718883550286508846516335790153998186614300493752317413537864956171451048868305380731285315760405126912629495204641829764230906698870575251861738847175174907714361155400020318026100833368698707674675548636610079631382774152211885405135045997623813094890524761824654025566099289284433567918244183562578"
                 },
                 "rms": "51663676247842478814965591806476166314018329779100758392678204435864101706276421100107118776199283981546682625125866769910726045178868995629346547166162207336629797340989495021248125384357605197654315399409367101440127312902706857104045262430326903112478154165057770802221835566137181123204394005042244715693211063132775814710986488082414421678086296488865286754803461178476006057306298883090062534704773627985221339716152111236985859907502262026150818487846053415153813804554830872575193396851274528558072704096323791923604931528594861707067370303707070124331485728734993074005001622035563911923643592706985074084035",
                 "rctxt":"60293229766149238310917923493206871325969738638348535857162249827595080348039120693847207728852550647187915587987334466582959087190830489258423645708276339586344792464665557038628519694583193692804909304334143467285824750999826903922956158114736424517794036832742439893595716442609416914557200249087236453529632524328334442017327755310827841619727229956823928475210644630763245343116656886668444813463622336899670813312626960927341115875144198394937398391514458462051400588820774593570752884252721428948286332429715774158007033348855655388287735570407811513582431434394169600082273657382209764160600063473877124656503",
                 "z":"70486542646006986754234343446999146345523665952265004264483059055307042644604796098478326629348068818272043688144751523020343994424262034067120716287162029288580118176972850899641747743901392814182335879624697285262287085187745166728443417803755667806532945136078671895589773743252882095592683767377435647759252676700424432160196120135306640079450582642553870190550840243254909737360996391470076977433525925799327058405911708739601511578904084479784054523375804238021939950198346585735956776232824298799161587408330541161160988641895300133750453032202142977745163418534140360029475702333980267724847703258887949227842"
              }"#;

        let string2 = r#"{
                 "n":"94752773003676215520340390286428145970577435379747248974837494389412082076547661891067434652276048522392442077335235388384984508621151996372559370276527598415204914831299768834758349425880859567795461321350412568232531440683627330032285846734752711268206613305069973750567165548816744023441650243801226580089078611213688037852063937259593837571943085718154394160122127891902723469618952030300431400181642597638732611518885616750614674142486169255034160093153314427704384760404032620300207070597238445621198019686315730573836193179483581719638565112589368474184957790046080767607443902003396643479910885086397579016949",
                 "s":"69412039600361800795429063472749802282903100455399422661844374992112119187258494682747330126416608111152308407310993289705267392969490079422545377823004584691698371089275086755756916575365439635768831063415050875440259347714303092581127338698890829662982679857654396534761554232914231213603075653629534596880597317047082696083166437821687405393805812336036647064899914817619861844092002636340952247588092904075021313598848481976631171767602864723880294787434756140969093416957086578979859382777377267118038126527549503876861370823520292585383483415337137062969402135540724590433024573312636828352734474276871187481042",
                 "r":{
                    "age":"90213462228557102785520674066817329607065098280886260103565465379328385444439123494955469500769864345819799623656302322427095342533906338563811194606234218499052997878891037890681314502037670093285650999142741875494918117023196753133733183769000368858655309319559871473827485381905587653145346258174022279515774231018893119774525087260785417971477049379955435611260162822960318458092151247522911151421981946748062572207451174079699745404644326303405628719711440096340436702151418321760375229323874027809433387030362543124015034968644213166988773750220839778654632868402703075643503247560457217265822566406481434257658",
                    "height":"5391629214047043372090966654120333203094518833743674393685635640778311836867622750170495792524304436281896432811455146477306501487333852472234525296058562723428516533641819658096275918819548576029252844651857904411902677509566190811985500618327955392620642519618001469964706236997279744030829811760566269297728600224591162795849338756438466021999870256717098048301453122263380103723520670896747657149140787953289875480355961166269553534983692005983375091110745903845958291035125718192228291126861666488320123420563113398593180368102996188897121307947248313167444374640621348136184583596487812048321382789134349482978",
                    "name":"77620276231641170120118188540269028385259155493880444038204934044861538875241492581309232702380290690573764595644801264135299029620031922004969464948925209245961139274806949465303313280327009910224580146266877846633558282936147503639084871235301887617650455108586169172459479774206351621894071684884758716731250212971549835402948093455393537573942251389197338609379019568250835525301455105289583537704528678164781839386485243301381405947043141406604458853106372019953011725448481499511842635580639867624862131749700424467221215201558826025502015289693451254344465767556321748122037274143231500322140291667454975911415",
                    "sex":"9589127953934298285127566793382980040568251918610023890115614786922171891298122457059996745443282235104668609426602496632245081143706804923757991602521162900045665258654877250328921570207935035808607238170708932487500434929591458680514420504595293934408583558084774019418964434729989362874165849497341625769388145344718883550286508846516335790153998186614300493752317413537864956171451048868305380731285315760405126912629495204641829764230906698870575251861738847175174907714361155400020318026100833368698707674675548636610079631382774152211885405135045997623813094890524761824654025566099289284433567918244183562578",
                    "master_secret": "51663676247842478814965591806476166314018329779100758392678204435864101706276421100107118776199283981546682625125866769910726045178868995629346547166162207336629797340989495021248125384357605197654315399409367101440127312902706857104045262430326903112478154165057770802221835566137181123204394005042244715693211063132775814710986488082414421678086296488865286754803461178476006057306298883090062534704773627985221339716152111236985859907502262026150818487846053415153813804554830872575193396851274528558072704096323791923604931528594861707067370303707070124331485728734993074005001622035563911923643592706985074084035"
                 },
                 "rctxt":"60293229766149238310917923493206871325969738638348535857162249827595080348039120693847207728852550647187915587987334466582959087190830489258423645708276339586344792464665557038628519694583193692804909304334143467285824750999826903922956158114736424517794036832742439893595716442609416914557200249087236453529632524328334442017327755310827841619727229956823928475210644630763245343116656886668444813463622336899670813312626960927341115875144198394937398391514458462051400588820774593570752884252721428948286332429715774158007033348855655388287735570407811513582431434394169600082273657382209764160600063473877124656503",
                 "z":"70486542646006986754234343446999146345523665952265004264483059055307042644604796098478326629348068818272043688144751523020343994424262034067120716287162029288580118176972850899641747743901392814182335879624697285262287085187745166728443417803755667806532945136078671895589773743252882095592683767377435647759252676700424432160196120135306640079450582642553870190550840243254909737360996391470076977433525925799327058405911708739601511578904084479784054523375804238021939950198346585735956776232824298799161587408330541161160988641895300133750453032202142977745163418534140360029475702333980267724847703258887949227842"
              }"#;

        let one = serde_json::from_str::<CredentialPrimaryPublicKey>(string1).unwrap();
        let two = serde_json::from_str::<CredentialPrimaryPublicKey>(string2).unwrap();

        assert_eq!(two, one);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn primary_equal_proof_conversion_works() {
        let string1 = r#"{
            "revealed_attrs":{ "name":"1139481716457488690172217916278103335" },
            "a_prime":"73051896986344783783621559954466052240337632808477729510525777007534198657123370460809453476237905269777928500034476888078179811369103091702326392092669222868996323974762333077146800752404116534730748685092400106417894776122280960547391515814302192999142386455183675790870578615457141270148590712693325301185445330992767208427208215818892089082206123243055148017865514286222759353929656015594529211154843197464055996993778878163967106658629893439206203941596066380562586058713924055616953462170537040600604826428201808405436865130230174790116739542071871153581967170346076628186863101926791732126528122264782281465094",
            "e":"26894279258848531841414955598838798345606055130059418263879278878511424413654641307014787224496208858379991228288791608261549931755104416",
            "v":"769593829417540943566687651216000708099616242062220026508500847265211856977241087739974159673381844796906987056271685312217722655254322996792650873775611656861273544234724432321045515309211146266498852589181986850053751764534235454974453901933962390148609111520973909072559803423360526975061164422239685006387576029266210201929872373313392190241424322333321394922891207577033519614434276723347140746548441162607411616008633618021962845423830579218345578253882839612570986096830936195064001459565147361336597305783767484298283647710212770870573787603073109857430854719681849489345098539472090186844042540487233617799636327572785715912348265648433678177765454231546725849288046905854444755145184654162149010359429569273734847400697627028832950969890252877892391103230391674009825009176344665382964776819962789472959504523580584494299815960094679820651071251157496967617834816772303813309035759721203718921501821175528106375",
            "m":{
                "age":"1143281854280323408461665818853228702279803847691030529301464848501919856277927436364331044530711281448694432838145799412204154542183613877104383361274202256495017144684827419222",
                "sex":"13123681697669364600723785784083768668401173003182555407713667959884184961072036088391942098105496874381346284841774772987179772727928471347011107103459387881602408580853389973314",
                "height":"5824877563809831190436025794795529331411852203759926644567286594845018041324472260994302109635777382645241758582661313361940262319244084725507113643699421966391425299602530147274"
             },
             "m1":"8583218861046444624186479147396651631579156942204850397797096661516116684243552483174250620744158944865553535495733571632663325011575249979223204777745326895517953843420687756433",
             "m2":"5731555078708393357614629066851705238802823277918949054467378429261691189252606979808518037016695141384783224302687321866277811431449642994233365265728281815807346591371594096297"
         }"#;
        let string2 = r#"{
            "revealed_attrs":{ "name":"1139481716457488690172217916278103335" },
            "a_prime":"73051896986344783783621559954466052240337632808477729510525777007534198657123370460809453476237905269777928500034476888078179811369103091702326392092669222868996323974762333077146800752404116534730748685092400106417894776122280960547391515814302192999142386455183675790870578615457141270148590712693325301185445330992767208427208215818892089082206123243055148017865514286222759353929656015594529211154843197464055996993778878163967106658629893439206203941596066380562586058713924055616953462170537040600604826428201808405436865130230174790116739542071871153581967170346076628186863101926791732126528122264782281465094",
            "e":"26894279258848531841414955598838798345606055130059418263879278878511424413654641307014787224496208858379991228288791608261549931755104416",
            "v":"769593829417540943566687651216000708099616242062220026508500847265211856977241087739974159673381844796906987056271685312217722655254322996792650873775611656861273544234724432321045515309211146266498852589181986850053751764534235454974453901933962390148609111520973909072559803423360526975061164422239685006387576029266210201929872373313392190241424322333321394922891207577033519614434276723347140746548441162607411616008633618021962845423830579218345578253882839612570986096830936195064001459565147361336597305783767484298283647710212770870573787603073109857430854719681849489345098539472090186844042540487233617799636327572785715912348265648433678177765454231546725849288046905854444755145184654162149010359429569273734847400697627028832950969890252877892391103230391674009825009176344665382964776819962789472959504523580584494299815960094679820651071251157496967617834816772303813309035759721203718921501821175528106375",
            "m":{
                "age":"1143281854280323408461665818853228702279803847691030529301464848501919856277927436364331044530711281448694432838145799412204154542183613877104383361274202256495017144684827419222",
                "sex":"13123681697669364600723785784083768668401173003182555407713667959884184961072036088391942098105496874381346284841774772987179772727928471347011107103459387881602408580853389973314",
                "height":"5824877563809831190436025794795529331411852203759926644567286594845018041324472260994302109635777382645241758582661313361940262319244084725507113643699421966391425299602530147274",
                "master_secret":"8583218861046444624186479147396651631579156942204850397797096661516116684243552483174250620744158944865553535495733571632663325011575249979223204777745326895517953843420687756433"
             },
             "m2":"5731555078708393357614629066851705238802823277918949054467378429261691189252606979808518037016695141384783224302687321866277811431449642994233365265728281815807346591371594096297"
         }"#;

        let one = serde_json::from_str::<PrimaryEqualProof>(string1).unwrap();
        let two = serde_json::from_str::<PrimaryEqualProof>(string2).unwrap();

        assert_eq!(two, one);
    }

    #[test]
    fn demo() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();
        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_value_hidden("master_secret", &master_secret.value().unwrap())
            .unwrap();
        credential_values_builder
            .add_dec_known("name", "1139481716457488690172217916278103335")
            .unwrap();
        credential_values_builder
            .add_dec_known(
                "sex",
                "5944657099558967239210949258394887428692050081607692519917050011144233115103",
            )
            .unwrap();
        credential_values_builder
            .add_dec_known("age", "28")
            .unwrap();
        credential_values_builder
            .add_dec_known("height", "175")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        )
        .unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        )
        .unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder
            .add_predicate("age", "GE", 18)
            .unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &cred_values,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    #[test]
    fn demo_revocation() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, issuance_by_default)
                .unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        let master_secret = Prover::new_master_secret().unwrap();

        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_value_hidden("master_secret", &master_secret.value().unwrap())
            .unwrap();
        credential_values_builder
            .add_dec_known("name", "1139481716457488690172217916278103335")
            .unwrap();
        credential_values_builder
            .add_dec_known(
                "sex",
                "5944657099558967239210949258394887428692050081607692519917050011144233115103",
            )
            .unwrap();
        credential_values_builder
            .add_dec_known("age", "28")
            .unwrap();
        credential_values_builder
            .add_dec_known("height", "175")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        let credential_issuance_nonce = new_nonce().unwrap();

        let rev_idx = 1;
        let (mut cred_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(
                "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &cred_values,
                &cred_pub_key,
                &cred_priv_key,
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &mut rev_reg,
                &rev_key_priv,
                &simple_tail_accessor,
            )
            .unwrap();

        let witness = Witness::new(
            rev_idx,
            max_cred_num,
            issuance_by_default,
            &rev_reg_delta.unwrap(),
            &simple_tail_accessor,
        )
        .unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &credential_issuance_nonce,
            Some(&rev_key_pub),
            Some(&rev_reg),
            Some(&witness),
        )
        .unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder
            .add_predicate("age", "GE", 18)
            .unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &cred_values,
                &cred_pub_key,
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();
        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                Some(&rev_key_pub),
                Some(&rev_reg),
            )
            .unwrap();
        assert_eq!(
            true,
            proof_verifier.verify(&proof, &proof_request_nonce).unwrap()
        );
    }
}

#[cfg(feature = "openssl_bn")]
mod openssl_tests {
    use anoncreds_clsignatures::error::ErrorKind;
    use anoncreds_clsignatures::*;
    use std::collections::BTreeSet;

    pub const PROVER_ID: &'static str = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";
    // Master secret is now called link secret.
    pub static LINK_SECRET: &'static str = "master_secret";

    mod test {
        use super::*;

        #[test]
        fn anoncreds_demo() {
            // // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();

            // Issuer creates GVT credential
            // 2. Issuer creates GVT credential schema
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("name").unwrap();
            credential_schema_builder.add_attr("sex").unwrap();
            credential_schema_builder.add_attr("age").unwrap();
            credential_schema_builder.add_attr("height").unwrap();
            let gvt_credential_schema = credential_schema_builder.finalize().unwrap();

            let mut non_credential_schema_builder =
                Issuer::new_non_credential_schema_builder().unwrap();
            non_credential_schema_builder
                .add_attr("master_secret")
                .unwrap();
            let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

            // 3. Issuer creates GVT credential definition
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, true)
                .unwrap();

            // 4. Issuer creates GVT revocation registry with IssuanceOnDemand type
            let gvt_max_cred_num = 5;
            let gvt_issuance_by_default = false;
            let (gvt_rev_key_pub, gvt_rev_key_priv, mut gvt_rev_reg, mut gvt_rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &gvt_credential_pub_key,
                    gvt_max_cred_num,
                    gvt_issuance_by_default,
                )
                .unwrap();

            let gvt_simple_tail_accessor =
                SimpleTailsAccessor::new(&mut gvt_rev_tails_generator).unwrap();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let gvt_credential_nonce = new_nonce().unwrap();

            // 6. Issuer creates GVT credential values
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_value_hidden("master_secret", &master_secret.value().unwrap())
                .unwrap();
            credential_values_builder
                .add_dec_known("name", "1139481716457488690172217916278103335")
                .unwrap();
            credential_values_builder
                .add_dec_known(
                    "sex",
                    "5944657099558967239210949258394887428692050081607692519917050011144233115103",
                )
                .unwrap();
            credential_values_builder
                .add_dec_known("age", "28")
                .unwrap();
            credential_values_builder
                .add_dec_known("height", "175")
                .unwrap();
            let gvt_credential_values = credential_values_builder.finalize().unwrap();

            // 7. Prover blinds hidden attributes
            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            // 8. Prover creates nonce used by Issuer to create correctness proof for signature
            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            // 9. Issuer signs GVT credential values
            let gvt_rev_idx = 1;
            let (mut gvt_credential_signature, gvt_signature_correctness_proof, gvt_rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                    gvt_rev_idx,
                    gvt_max_cred_num,
                    gvt_issuance_by_default,
                    &mut gvt_rev_reg,
                    &gvt_rev_key_priv,
                    &gvt_simple_tail_accessor,
                )
                .unwrap();

            // 10. Prover creates GVT witness
            let gvt_witness = Witness::new(
                gvt_rev_idx,
                gvt_max_cred_num,
                gvt_issuance_by_default,
                &gvt_rev_reg_delta.unwrap(),
                &gvt_simple_tail_accessor,
            )
            .unwrap();

            // 11. Prover processes GVT credential signature
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values,
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                Some(&gvt_rev_key_pub),
                Some(&gvt_rev_reg),
                Some(&gvt_witness),
            )
            .unwrap();

            // Issuer creates XYZ credential
            // 12. Issuer creates XYZ credential schema
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("period").unwrap();
            credential_schema_builder.add_attr("status").unwrap();
            let xyz_credential_schema = credential_schema_builder.finalize().unwrap();

            // 13. Issuer creates XYZ credential definition (with revocation keys)
            let (
                xyz_credential_pub_key,
                xyz_credential_priv_key,
                xyz_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, true)
                .unwrap();

            // 14. Issuer creates XYZ revocation registry with IssuanceByDefault type
            let xyz_max_cred_num = 5;
            let xyz_issuance_by_default = true;
            let (xyz_rev_key_pub, xyz_rev_key_priv, mut xyz_rev_reg, mut xyz_rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &xyz_credential_pub_key,
                    xyz_max_cred_num,
                    xyz_issuance_by_default,
                )
                .unwrap();

            let xyz_simple_tail_accessor =
                SimpleTailsAccessor::new(&mut xyz_rev_tails_generator).unwrap();

            // 15. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let xyz_credential_nonce = new_nonce().unwrap();

            // 16. Issuer creates XYZ credential values
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_value_hidden("master_secret", &master_secret.value().unwrap())
                .unwrap();
            credential_values_builder
                .add_dec_known("status", "51792877103171595686471452153480627530895")
                .unwrap();
            credential_values_builder
                .add_dec_known("period", "8")
                .unwrap();
            let xyz_credential_values = credential_values_builder.finalize().unwrap();

            // 17. Prover blinds hidden attributes
            let (
                xyz_blinded_credential_secrets,
                xyz_credential_secrets_blinding_factors,
                xyz_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &xyz_credential_pub_key,
                &xyz_credential_key_correctness_proof,
                &xyz_credential_values,
                &xyz_credential_nonce,
            )
            .unwrap();

            // 18. Prover creates nonce used by Issuer to create correctness proof for signature
            let xyz_credential_issuance_nonce = new_nonce().unwrap();

            // 19. Issuer signs XYZ credential values
            let xyz_rev_idx = 1;
            let (mut xyz_credential_signature, xyz_signature_correctness_proof, xyz_rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &xyz_blinded_credential_secrets,
                    &xyz_blinded_credential_secrets_correctness_proof,
                    &xyz_credential_nonce,
                    &xyz_credential_issuance_nonce,
                    &xyz_credential_values,
                    &xyz_credential_pub_key,
                    &xyz_credential_priv_key,
                    xyz_rev_idx,
                    xyz_max_cred_num,
                    xyz_issuance_by_default,
                    &mut xyz_rev_reg,
                    &xyz_rev_key_priv,
                    &xyz_simple_tail_accessor,
                )
                .unwrap();
            assert!(xyz_rev_reg_delta.is_none());
            let xyz_rev_reg_delta = RevocationRegistryDelta::from(&xyz_rev_reg);

            // 20. Prover creates XYZ witness
            let xyz_witness = Witness::new(
                xyz_rev_idx,
                xyz_max_cred_num,
                xyz_issuance_by_default,
                &xyz_rev_reg_delta,
                &xyz_simple_tail_accessor,
            )
            .unwrap();

            // 21. Prover processes XYZ credential signature
            Prover::process_credential_signature(
                &mut xyz_credential_signature,
                &xyz_credential_values,
                &xyz_signature_correctness_proof,
                &xyz_credential_secrets_blinding_factors,
                &xyz_credential_pub_key,
                &xyz_credential_issuance_nonce,
                Some(&xyz_rev_key_pub),
                Some(&xyz_rev_reg),
                Some(&xyz_witness),
            )
            .unwrap();

            // 22. Verifier creates sub proof request related to GVT credential
            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            sub_proof_request_builder.add_revealed_attr("name").unwrap();
            sub_proof_request_builder
                .add_predicate("age", "GE", 18)
                .unwrap();
            let gvt_sub_proof_request = sub_proof_request_builder.finalize().unwrap();

            // 23. Verifier creates sub proof request related to XYZ credential
            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            sub_proof_request_builder
                .add_revealed_attr("status")
                .unwrap();
            sub_proof_request_builder
                .add_predicate("period", "GE", 4)
                .unwrap();
            let xyz_sub_proof_request = sub_proof_request_builder.finalize().unwrap();

            // 24. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 25. Prover creates proof for two sub proof requests
            let mut proof_builder = Prover::new_proof_builder().unwrap();

            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    Some(&gvt_rev_reg),
                    Some(&gvt_witness),
                )
                .unwrap();

            proof_builder
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_signature,
                    &xyz_credential_values,
                    &xyz_credential_pub_key,
                    Some(&xyz_rev_reg),
                    Some(&xyz_witness),
                )
                .unwrap();

            let proof = proof_builder.finalize(&nonce).unwrap();

            // 26. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    Some(&gvt_rev_key_pub),
                    Some(&gvt_rev_reg),
                )
                .unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_pub_key,
                    Some(&xyz_rev_key_pub),
                    Some(&xyz_rev_reg),
                )
                .unwrap();

            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn credential_with_negative_attribute_and_empty_proof_works() {
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("height").unwrap();
            let credential_schema = credential_schema_builder.finalize().unwrap();

            let non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
            let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

            let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            let credential_nonce = new_nonce().unwrap();

            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_dec_known("height", "-1")
                .unwrap();
            let cred_values = credential_values_builder.finalize().unwrap();

            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &cred_pub_key,
                &cred_key_correctness_proof,
                &cred_values,
                &credential_nonce,
            )
            .unwrap();

            let cred_issuance_nonce = new_nonce().unwrap();

            let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
                "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &cred_issuance_nonce,
                &cred_values,
                &cred_pub_key,
                &cred_priv_key,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut cred_signature,
                &cred_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &cred_pub_key,
                &cred_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            sub_proof_request_builder
                .add_predicate("height", "GE", -2)
                .unwrap();
            let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &cred_signature,
                    &cred_values,
                    &cred_pub_key,
                    None,
                    None,
                )
                .unwrap();

            let proof_request_nonce = new_nonce().unwrap();
            let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &cred_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_primary_proof_only() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Issuer creates credential values
            let credential_values =
                helpers::gvt_credential_values(&Prover::new_master_secret().unwrap());

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds hidden attributes
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 10. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 11. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_issuance_on_demand() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry with IssuanceOnDemand type
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer creates and sign credential values
            let credential_values =
                helpers::gvt_credential_values(&Prover::new_master_secret().unwrap());

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds hidden attributes
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            // 8. Prover creates witness
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &rev_reg_delta.unwrap(),
                &simple_tail_accessor,
            )
            .unwrap();

            // 9. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 10. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 11. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 12. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 13. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_issuance_by_default() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 4. Issuer creates GVT revocation registry with IssuanceByDefault type
            let max_cred_num = 5;
            let issuance_by_default = true;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Prover creates master secret with credential values
            let credential_values =
                helpers::gvt_credential_values(&Prover::new_master_secret().unwrap());

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 8. Issuer creates and sign credential values
            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            assert!(rev_reg_delta.is_none());

            let rev_reg_delta = RevocationRegistryDelta::from(&rev_reg);

            // 9. Prover creates witness
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &rev_reg_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            // 10. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 11. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 12. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 13. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 14. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_used_for_proof() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values(&master_secret);

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values,
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs XYZ credential for Prover
            let xyz_credential_schema = helpers::xyz_credential_schema();
            let (
                xyz_credential_pub_key,
                xyz_credential_priv_key,
                xyz_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, false)
                .unwrap();

            let xyz_credential_nonce = new_nonce().unwrap();
            let xyz_credential_values = helpers::xyz_credential_values(&master_secret);

            let (
                xyz_blinded_credential_secrets,
                xyz_credential_secrets_blinding_factors,
                xyz_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &xyz_credential_pub_key,
                &xyz_credential_key_correctness_proof,
                &xyz_credential_values,
                &xyz_credential_nonce,
            )
            .unwrap();

            let xyz_credential_issuance_nonce = new_nonce().unwrap();

            let (mut xyz_credential_signature, xyz_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &xyz_blinded_credential_secrets,
                    &xyz_blinded_credential_secrets_correctness_proof,
                    &xyz_credential_nonce,
                    &xyz_credential_issuance_nonce,
                    &xyz_credential_values,
                    &xyz_credential_pub_key,
                    &xyz_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut xyz_credential_signature,
                &xyz_credential_values,
                &xyz_signature_correctness_proof,
                &xyz_credential_secrets_blinding_factors,
                &xyz_credential_pub_key,
                &xyz_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request();
            let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_signature,
                    &xyz_credential_values,
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and XYZ sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_different_master_secret() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values(&master_secret);

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values,
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs PQR credential for Prover
            let pqr_credential_schema = helpers::pqr_credential_schema();
            let (
                pqr_credential_pub_key,
                pqr_credential_priv_key,
                pqr_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&pqr_credential_schema, &non_credential_schema, false)
                .unwrap();

            // The second credential has a different link secret
            let master_secret_1 = Prover::new_master_secret().unwrap();

            let pqr_credential_nonce = new_nonce().unwrap();
            let pqr_credential_values = helpers::pqr_credential_values(&master_secret_1);

            let (
                pqr_blinded_credential_secrets,
                pqr_credential_secrets_blinding_factors,
                pqr_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &pqr_credential_pub_key,
                &pqr_credential_key_correctness_proof,
                &pqr_credential_values,
                &pqr_credential_nonce,
            )
            .unwrap();

            let pqr_credential_issuance_nonce = new_nonce().unwrap();

            let (mut pqr_credential_signature, pqr_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &pqr_blinded_credential_secrets,
                    &pqr_blinded_credential_secrets_correctness_proof,
                    &pqr_credential_nonce,
                    &pqr_credential_issuance_nonce,
                    &pqr_credential_values,
                    &pqr_credential_pub_key,
                    &pqr_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut pqr_credential_signature,
                &pqr_credential_values,
                &pqr_signature_correctness_proof,
                &pqr_credential_secrets_blinding_factors,
                &pqr_credential_pub_key,
                &pqr_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request_1();
            let pqr_sub_proof_request = helpers::pqr_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_signature,
                    &pqr_credential_values,
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and PQR sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            // Verifier expects link secret (named `master_secret` here) to be same in both credentials
            proof_verifier.add_common_attribute(LINK_SECRET).unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // The proof will fail since value of `master_secret` is different in both credentials
            assert_eq!(
                ErrorKind::ProofRejected,
                proof_verifier.verify(&proof, &nonce).unwrap_err().kind()
            );
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_common_attribute_same_value() {
            // 2 credentials have attribute with same name and same value and the proof proves that values are same.
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values(&master_secret);

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values,
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs PQR credential for Prover
            let pqr_credential_schema = helpers::pqr_credential_schema();
            let (
                pqr_credential_pub_key,
                pqr_credential_priv_key,
                pqr_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&pqr_credential_schema, &non_credential_schema, false)
                .unwrap();

            let pqr_credential_nonce = new_nonce().unwrap();
            // PQR credential has same value for attribute name as the GVT credential
            let pqr_credential_values = helpers::pqr_credential_values(&master_secret);

            let (
                pqr_blinded_credential_secrets,
                pqr_credential_secrets_blinding_factors,
                pqr_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &pqr_credential_pub_key,
                &pqr_credential_key_correctness_proof,
                &pqr_credential_values,
                &pqr_credential_nonce,
            )
            .unwrap();

            let pqr_credential_issuance_nonce = new_nonce().unwrap();

            let (mut pqr_credential_signature, pqr_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &pqr_blinded_credential_secrets,
                    &pqr_blinded_credential_secrets_correctness_proof,
                    &pqr_credential_nonce,
                    &pqr_credential_issuance_nonce,
                    &pqr_credential_values,
                    &pqr_credential_pub_key,
                    &pqr_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut pqr_credential_signature,
                &pqr_credential_values,
                &pqr_signature_correctness_proof,
                &pqr_credential_secrets_blinding_factors,
                &pqr_credential_pub_key,
                &pqr_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request_1();
            let pqr_sub_proof_request = helpers::pqr_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            // name attribute value is same across both gvt and pqr credentials
            proof_builder.add_common_attribute("name").unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_signature,
                    &pqr_credential_values,
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and PQR sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            // Verifier expects link secret (named `master_secret` here) to be same in both credentials
            proof_verifier.add_common_attribute(LINK_SECRET).unwrap();
            // Verifier expects attribute `name` to be same in both credentials
            proof_verifier.add_common_attribute("name").unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_common_attribute_different_value() {
            // 2 credentials have attribute with same name but different values and the proof fails to prove that they have same value.
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values(&master_secret);

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values,
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs PQR credential for Prover
            let pqr_credential_schema = helpers::pqr_credential_schema();
            let (
                pqr_credential_pub_key,
                pqr_credential_priv_key,
                pqr_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&pqr_credential_schema, &non_credential_schema, false)
                .unwrap();

            let pqr_credential_nonce = new_nonce().unwrap();
            let pqr_credential_values = helpers::pqr_credential_values_1(&master_secret);

            let (
                pqr_blinded_credential_secrets,
                pqr_credential_secrets_blinding_factors,
                pqr_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &pqr_credential_pub_key,
                &pqr_credential_key_correctness_proof,
                &pqr_credential_values,
                &pqr_credential_nonce,
            )
            .unwrap();

            let pqr_credential_issuance_nonce = new_nonce().unwrap();

            let (mut pqr_credential_signature, pqr_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &pqr_blinded_credential_secrets,
                    &pqr_blinded_credential_secrets_correctness_proof,
                    &pqr_credential_nonce,
                    &pqr_credential_issuance_nonce,
                    &pqr_credential_values,
                    &pqr_credential_pub_key,
                    &pqr_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut pqr_credential_signature,
                &pqr_credential_values,
                &pqr_signature_correctness_proof,
                &pqr_credential_secrets_blinding_factors,
                &pqr_credential_pub_key,
                &pqr_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request_1();
            let pqr_sub_proof_request = helpers::pqr_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            // name attribute value is different in both gvt and pqr credentials
            proof_builder.add_common_attribute("name").unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_signature,
                    &pqr_credential_values,
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and XYZ sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            // Verifier expects link secret (named `master_secret` here) to be same in both credentials
            proof_verifier.add_common_attribute(LINK_SECRET).unwrap();
            // Verifier expects attribute `name` to be same in both credentials
            proof_verifier.add_common_attribute("name").unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // The proof will fail since value of `name` is different in both credentials
            assert_eq!(
                ErrorKind::ProofRejected,
                proof_verifier.verify(&proof, &nonce).unwrap_err().kind()
            );
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_missing_common_attribute() {
            // 2 credentials are used to create a proof that they both have a certain attribute with same name and value but that is not the case.
            // The proof verification fails.

            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values(&master_secret);

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values,
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs XYZ credential for Prover
            let xyz_credential_schema = helpers::xyz_credential_schema();
            let (
                xyz_credential_pub_key,
                xyz_credential_priv_key,
                xyz_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, false)
                .unwrap();

            let xyz_credential_nonce = new_nonce().unwrap();
            let xyz_credential_values = helpers::xyz_credential_values(&master_secret);

            let (
                xyz_blinded_credential_secrets,
                xyz_credential_secrets_blinding_factors,
                xyz_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &xyz_credential_pub_key,
                &xyz_credential_key_correctness_proof,
                &xyz_credential_values,
                &xyz_credential_nonce,
            )
            .unwrap();

            let xyz_credential_issuance_nonce = new_nonce().unwrap();

            let (mut xyz_credential_signature, xyz_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &xyz_blinded_credential_secrets,
                    &xyz_blinded_credential_secrets_correctness_proof,
                    &xyz_credential_nonce,
                    &xyz_credential_issuance_nonce,
                    &xyz_credential_values,
                    &xyz_credential_pub_key,
                    &xyz_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut xyz_credential_signature,
                &xyz_credential_values,
                &xyz_signature_correctness_proof,
                &xyz_credential_secrets_blinding_factors,
                &xyz_credential_pub_key,
                &xyz_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request();
            let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_signature,
                    &xyz_credential_values,
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and XYZ sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            // Verifier expects link secret (named `master_secret` here) to be same in both credentials
            proof_verifier.add_common_attribute(LINK_SECRET).unwrap();
            // Verifier expects attribute `name` to be same in both credentials
            proof_verifier.add_common_attribute("name").unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // The proof will fail since `name` is not present in XYZ credential
            assert_eq!(
                ErrorKind::ProofRejected,
                proof_verifier.verify(&proof, &nonce).unwrap_err().kind()
            );
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_three_credentials_proving_first() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer issues first credential
            let master_secret_1 = Prover::new_master_secret().unwrap();
            let credential_values_1 = helpers::gvt_credential_values(&master_secret_1);

            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values_1,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (mut credential_signature_1, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_1,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_1,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            let mut full_delta = rev_reg_delta.unwrap();

            let mut witness_1 = Witness::new(
                rev_idx_1,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values_1,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let master_secret_2 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_2);

            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_2 = 2;
            let (mut credential_signature_2, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_2,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            let witness_2 = Witness::new(
                rev_idx_2,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 6. Issuer issues third credential
            let master_secret_3 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_3);

            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_3 = 3;
            let (mut credential_signature_3, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_3,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            let witness_3 = Witness::new(
                rev_idx_3,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_3,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_3),
            )
            .unwrap();

            // 7. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 8. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving first credential
            // 9. Prover updates witness_1
            witness_1
                .update(rev_idx_1, max_cred_num, &full_delta, &simple_tail_accessor)
                .unwrap();

            // 10. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_1,
                    &credential_values_1,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_1),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 11. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_three_credentials_revoke_first_proving_third() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer issues first credential
            let master_secret_1 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_1);

            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (mut credential_signature_1, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_1,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            let mut full_delta = rev_reg_delta.unwrap();

            let witness_1 = Witness::new(
                rev_idx_1,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let master_secret_2 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_2);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx_2 = 2;
            let (mut credential_signature_2, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_2,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            let witness_2 = Witness::new(
                rev_idx_2,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 6. Issuer issues third credential
            let master_secret_3 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_3);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_3 = 3;
            let (mut credential_signature_3, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_3,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();
            let mut delta_for_third = RevocationRegistryDelta::from(&rev_reg);

            let mut witness_3 = Witness::new(
                rev_idx_3,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_3,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_3),
            )
            .unwrap();

            // 7. Issuer revokes first credential
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx_1,
                &simple_tail_accessor,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();
            delta_for_third.merge(&rev_reg_delta).unwrap();

            // 8. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 9. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving third credential
            // 10. Prover updates witness_1
            witness_3
                .update(
                    rev_idx_3,
                    max_cred_num,
                    &delta_for_third,
                    &simple_tail_accessor,
                )
                .unwrap();

            // 11. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_3,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_3),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_three_credentials_revoke_third_proving_first() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer issues first credential
            let master_secret_1 = Prover::new_master_secret().unwrap();
            let credential_values_1 = helpers::gvt_credential_values(&master_secret_1);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values_1,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (mut credential_signature_1, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_1,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_1,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            let mut full_delta = rev_reg_delta.unwrap();

            let mut witness_1 = Witness::new(
                rev_idx_1,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values_1,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let master_secret_2 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_2);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_2 = 2;
            let (mut credential_signature_2, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_2,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            let witness_2 = Witness::new(
                rev_idx_2,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 6. Issuer issues third credential
            let master_secret_3 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_3);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_3 = 3;
            let (mut credential_signature_3, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_3,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            let witness_3 = Witness::new(
                rev_idx_3,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_3,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_3),
            )
            .unwrap();

            // 7. Issuer revokes third credential
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx_3,
                &simple_tail_accessor,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();

            // 8. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 9. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving first credential
            // 10. Prover updates witness_1
            witness_1
                .update(rev_idx_1, max_cred_num, &full_delta, &simple_tail_accessor)
                .unwrap();

            // 11. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_1,
                    &credential_values_1,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_1),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_three_credentials_revoke_first_and_third_proving_second(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer issues first credential
            let master_secret_1 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_1);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (mut credential_signature_1, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_1,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            let mut full_delta = rev_reg_delta.unwrap();

            let witness_1 = Witness::new(
                rev_idx_1,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let master_secret_2 = Prover::new_master_secret().unwrap();
            let credential_values_2 = helpers::gvt_credential_values(&master_secret_2);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values_2,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_2 = 2;
            let (mut credential_signature_2, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_2,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_2,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();
            let mut delta_for_second = RevocationRegistryDelta::from(&rev_reg);

            let mut witness_2 = Witness::new(
                rev_idx_2,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values_2,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 6. Issuer issues third credential
            let master_secret_3 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_3);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_3 = 3;
            let (mut credential_signature_3, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_3,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            let rev_reg_delta = rev_reg_delta.unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();
            delta_for_second.merge(&rev_reg_delta).unwrap();

            let witness_3 = Witness::new(
                rev_idx_3,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_3,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_3),
            )
            .unwrap();

            // 7. Issuer revokes first credential
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx_1,
                &simple_tail_accessor,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();
            delta_for_second.merge(&rev_reg_delta).unwrap();

            // 8. Issuer revokes third credential
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx_3,
                &simple_tail_accessor,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();
            delta_for_second.merge(&rev_reg_delta).unwrap();

            // 9. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 10. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving second credential
            // 11. Prover updates witness_2
            witness_2
                .update(
                    rev_idx_2,
                    max_cred_num,
                    &delta_for_second,
                    &simple_tail_accessor,
                )
                .unwrap();

            // 12. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_2,
                    &credential_values_2,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_2),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 13. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_two_credentials_proving_first_with_outdated_witness(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer issues first credential
            let master_secret_1 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_1);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (mut credential_signature_1, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_1,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            let mut full_delta = rev_reg_delta.unwrap();

            let witness_1 = Witness::new(
                rev_idx_1,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let master_secret_2 = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret_2);
            let credential_nonce = new_nonce().unwrap();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_2 = 2;
            let (mut credential_signature_2, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_2,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            let witness_2 = Witness::new(
                rev_idx_2,
                max_cred_num,
                issuance_by_default,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 7. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 8. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving first credential
            // 9. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_1,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_1),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 10. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_proof_created_before_credential_revoked() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            // 8. Prover creates witness
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &rev_reg_delta.unwrap(),
                &simple_tail_accessor,
            )
            .unwrap();

            // 9. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 10. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 11. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 12. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 14. Issuer revokes credential used for proof building
            Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor)
                .unwrap();

            // 15. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_proof_created_after_credential_revoked() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            // 9. Prover creates witness
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &rev_reg_delta.unwrap(),
                &simple_tail_accessor,
            )
            .unwrap();

            // 10. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 11. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 12. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 13. Issuer revokes credential
            Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor)
                .unwrap();

            // 14. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 15. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_proof_created_after_credential_revoked_issuance_by_default() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = true;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            assert!(rev_reg_delta.is_none());
            let rev_reg_delta = RevocationRegistryDelta::from(&rev_reg);

            // 9. Prover creates witness
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &rev_reg_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            // 10. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 11. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 12. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 13. Issuer revokes credential
            Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor)
                .unwrap();

            // 14. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 15. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_recovery_credential() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 4. Issuer creates revocation registry with IssuanceOnDemand type
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            // 8. Prover creates witness
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &rev_reg_delta.unwrap(),
                &simple_tail_accessor,
            )
            .unwrap();

            // 9. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 11. Verifier creates proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 12. Prover builds proof
            let nonce = new_nonce().unwrap();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 13. Verifier verifies proof (Proof is valid)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());

            // 14. Issuer revokes credential
            Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor)
                .unwrap();

            // 15. Verifier verifies proof (Proof is not valid)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());

            // 16. Issuer recoveries credential
            Issuer::recovery_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor)
                .unwrap();

            // 17. Verifier verifies proof (Proof is valid again)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_update_revocation_registry() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 4. Issuer creates revocation registry with IssuanceOnDemand type
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            // 8. Prover creates witness
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &rev_reg_delta.unwrap(),
                &simple_tail_accessor,
            )
            .unwrap();

            // 9. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 11. Verifier creates proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 12. Prover builds proof
            let nonce = new_nonce().unwrap();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 13. Verifier verifies proof (Proof is valid)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());

            // 14. Issuer revokes credential
            let mut revoked = BTreeSet::new();
            revoked.insert(rev_idx);
            Issuer::update_revocation_registry(
                &mut rev_reg,
                max_cred_num,
                BTreeSet::new(),
                revoked.clone(),
                &simple_tail_accessor,
            )
            .unwrap();

            // 15. Verifier verifies proof (Proof is not valid)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());

            // 16. Issuer recovers credential
            Issuer::update_revocation_registry(
                &mut rev_reg,
                max_cred_num,
                revoked.clone(),
                BTreeSet::new(),
                &simple_tail_accessor,
            )
            .unwrap();

            // 17. Verifier verifies proof (Proof is valid again)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        #[ignore]
        fn anoncreds_works_for_full_accumulator() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry for only 1 credential
            let max_cred_num = 1;
            let (_, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)
                    .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            Issuer::sign_credential_with_revoc(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
                1,
                max_cred_num,
                false,
                &mut rev_reg,
                &rev_key_priv,
                &simple_tail_accessor,
            )
            .unwrap();

            // 8. Issuer creates and sign second credential values
            let _res = Issuer::sign_credential_with_revoc(
                &format!("{}2", PROVER_ID),
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
                2,
                max_cred_num,
                false,
                &mut rev_reg,
                &rev_key_priv,
                &simple_tail_accessor,
            );
            // assert_eq!(
            //     ErrorKind::RevocationAccumulatorIsFull,
            //     res.unwrap_err().kind()
            // );
        }

        #[test]
        #[ignore]
        fn anoncreds_works_for_reissue_credential_with_same_index() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 1;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)
                    .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            let rev_idx = 1;

            // FIRST Issue of credential
            // 4. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 8. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    false,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();

            let mut full_delta = rev_reg_delta.unwrap();

            // 9. Prover creates witness
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                false,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            // 10. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // Create proof by issued credential
            // 11. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 12. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 13. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 14. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(true, proof_verifier.verify(&proof, &nonce).unwrap());

            // 15. Issuer revokes credential used for proof building
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                rev_idx,
                max_cred_num,
                &simple_tail_accessor,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();

            // 16. Verifier verifies proof after revocation
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());

            // Reissue credential with different values but same rev_index

            // 16. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let new_credential_nonce = new_nonce().unwrap();

            // 17. Prover blinds master secret
            let (
                new_blinded_credential_secrets,
                new_credential_secrets_blinding_factors,
                new_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &new_credential_nonce,
            )
            .unwrap();

            // 18. Prover creates nonce used Issuer to new credential issue
            let new_credential_issuance_nonce = new_nonce().unwrap();

            // 19. Issuer creates and signs new credential values
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_value_hidden("master_secret", &master_secret.value().unwrap())
                .unwrap();
            credential_values_builder
                .add_dec_known("name", "1139481716457488690172217916278103335")
                .unwrap();
            credential_values_builder
                .add_dec_known(
                    "sex",
                    "5944657099558967239210949258394887428692050081607692519917050011144233115103",
                )
                .unwrap();
            credential_values_builder
                .add_dec_known("age", "44")
                .unwrap();
            credential_values_builder
                .add_dec_known("height", "165")
                .unwrap();
            let credential_values = credential_values_builder.finalize().unwrap();

            let (mut new_credential_signature, new_signature_correctness_proof, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &new_blinded_credential_secrets,
                    &new_blinded_credential_secrets_correctness_proof,
                    &new_credential_nonce,
                    &new_credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    false,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                false,
                &full_delta,
                &simple_tail_accessor,
            )
            .unwrap();

            // 20. Prover processes new credential signature
            Prover::process_credential_signature(
                &mut new_credential_signature,
                &credential_values,
                &new_signature_correctness_proof,
                &new_credential_secrets_blinding_factors,
                &credential_pub_key,
                &new_credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();
            // 21. Prover creates proof using new credential
            let mut new_proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            new_proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &new_credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();

            let new_proof = proof_builder.finalize(&nonce).unwrap();

            // 22. Verifier verifies proof created by new credential
            let mut new_proof_verifier = Verifier::new_proof_verifier().unwrap();
            new_proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(new_proof_verifier.verify(&new_proof, &nonce).unwrap());

            // 23. Verifier verifies proof created before the first credential had been revoked
            let mut old_proof_verifier = Verifier::new_proof_verifier().unwrap();
            old_proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, old_proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_missed_process_credential_step() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (credential_signature, _) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Verifier creates nonce and sub proof request
            let nonce = new_nonce().unwrap();
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 9. Prover creates proof by sub proof request not corresponded to verifier proof request
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 10. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_proof_created_with_wrong_master_secret() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values wrong keys
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates nonce and sub proof request
            let nonce = new_nonce().unwrap();
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 10. Prover creates proof by sub proof request not corresponded to verifier proof request
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            let another_master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&another_master_secret);

            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            let proof = proof_builder.finalize(&nonce).unwrap();

            // 11. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_used_different_nonce() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values wrong keys
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 10. Prover creates proof by sub proof request not corresponded to verifier proof request
            let nonce_for_proof_creation = new_nonce().unwrap();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            let proof = proof_builder.finalize(&nonce_for_proof_creation).unwrap();

            // 11. Verifier verifies proof
            let nonce_for_proof_verification = new_nonce().unwrap();

            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(
                false,
                proof_verifier
                    .verify(&proof, &nonce_for_proof_verification)
                    .unwrap()
            );
        }

        #[test]
        fn anoncreds_works_for_proof_not_correspond_to_verifier_proof_request() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Prover creates proof by sub proof request not corresponded to verifier proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            let nonce = new_nonce().unwrap();

            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 10. Verifier verifies proof
            let xyz_credential_schema = helpers::xyz_credential_schema();
            let (xyz_credential_pub_key, _, _) =
                Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, false)
                    .unwrap();
            let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            let res = proof_verifier.verify(&proof, &nonce);
            assert_eq!(ErrorKind::ProofRejected, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_create_keys_works_for_empty_credential_schema() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            let credential_schema = credential_schema_builder.finalize().unwrap();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let res = Issuer::new_credential_def(&credential_schema, &non_credential_schema, false);
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_create_revocation_registry_works_for_keys_without_revocation_part() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(without revocation part)
            let (credential_pub_key, _, _) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let res = Issuer::new_revocation_registry_def(&credential_pub_key, 5, false);
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        #[ignore]
        fn issuer_revoke_works_for_invalid_revocation_index() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, _, _) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let (_, _, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)
                    .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer tries revoke not not added index
            let rev_idx = 1;
            let _res = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx,
                &simple_tail_accessor,
            );
            // assert_eq!(
            //     ErrorKind::InvalidRevocationAccumulatorIndex,
            //     res.unwrap_err().kind()
            // );
        }

        #[test]
        fn issuer_sign_credential_works_for_credential_values_not_correspond_to_issuer_keys() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::xyz_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values not correspondent to issuer keys

            // 8. Issuer signs wrong credential values
            let res = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            );

            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_builder_add_sub_proof_works_for_credential_values_not_correspond_to_credential_schema(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();

            // Wrong credential values
            let credential_values = helpers::xyz_credential_values(&master_secret);

            let sub_proof_request = helpers::gvt_sub_proof_request();

            let res = proof_builder.add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_signature,
                &credential_values,
                &credential_pub_key,
                None,
                None,
            );

            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_builder_add_sub_proof_works_for_credential_not_satisfy_to_sub_proof_request() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates sub proof request
            let sub_proof_request = helpers::xyz_sub_proof_request();

            // 10. Prover creates proof by credential not correspondent to proof request
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            let res = proof_builder.add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_signature,
                &credential_values,
                &credential_pub_key,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_builder_add_sub_proof_works_for_credential_not_contained_requested_attribute() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates sub proof request
            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            sub_proof_request_builder
                .add_revealed_attr("status")
                .unwrap();
            let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

            // 10. Prover creates proof by credential not contained requested attribute
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            let res = proof_builder.add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_signature,
                &credential_values,
                &credential_pub_key,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_builder_add_sub_proof_works_for_credential_not_satisfied_requested_predicate() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates sub proof request
            let mut gvt_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            gvt_sub_proof_request_builder
                .add_revealed_attr("name")
                .unwrap();
            gvt_sub_proof_request_builder
                .add_predicate("age", "GE", 50)
                .unwrap();
            let sub_proof_request = gvt_sub_proof_request_builder.finalize().unwrap();

            // 10. Prover creates proof by credential value not satisfied predicate
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            let res = proof_builder.add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_signature,
                &credential_values,
                &credential_pub_key,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_verifier_add_sub_proof_request_works_for_credential_schema_not_satisfied_to_sub_proof_request(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, _, _) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Verifier build proof verifier
            let sub_proof_request = helpers::gvt_sub_proof_request();
            let xyz_credential_schema = helpers::xyz_credential_schema();

            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            let res = proof_verifier.add_sub_proof_request(
                &sub_proof_request,
                &xyz_credential_schema,
                &non_credential_schema,
                &credential_pub_key,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_blind_credential_secrets_works_for_key_correctness_proof_not_correspond_to_public_key(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 2. Issuer creates GVT credential definition
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (gvt_credential_pub_key, _, _) =
                Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Issuer creates XYZ credential definition
            let xyz_credential_schema = helpers::xyz_credential_schema();
            let (_, _, xyz_credential_key_correctness_proof) =
                Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let gvt_credential_nonce = new_nonce().unwrap();

            // 5. Prover blind master secret by gvt_public_key and xyz_key_correctness_proof
            let res = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &xyz_credential_key_correctness_proof,
                &credential_values,
                &gvt_credential_nonce,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_sign_credential_works_for_prover_used_different_nonce_to_blind_credential_secrets(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            let other_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &credential_values,
                    &other_nonce,
                )
                .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values
            let res = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_sign_credential_works_for_keys_not_correspond_to_blinded_credential_secrets_correctness_proof(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates GVT credential definition
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (gvt_credential_pub_key, _, gvt_credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 2. Issuer creates XYZ credential definition
            let credential_schema = helpers::xyz_credential_schema();
            let (xyz_credential_pub_key, xyz_credential_priv_key, _) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let gvt_credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret by GVT key
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &gvt_credential_pub_key,
                    &gvt_credential_key_correctness_proof,
                    &gvt_credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values
            let xyz_credential_values = helpers::xyz_credential_values(&master_secret);

            // 8. Issuer signs XYZ credential values for Prover
            let res = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &xyz_credential_values,
                &xyz_credential_pub_key,
                &xyz_credential_priv_key,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_sign_credential_works_for_blinded_credential_secrets_not_correspond_to_blinded_credential_secrets_correctness_proof(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates GVT credential definition
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 2. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 3. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 4. Prover blinds master secret
            let (_, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 5. Prover blinds master secret second time
            let (blinded_credential_secrets, _, _) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values for Prover
            let res = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_process_credential_signature_works_for_issuer_used_different_nonce() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let different_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &different_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 9. Prover processes credential signature
            let res = Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_process_credential_signature_works_for_credential_signature_not_correspond_to_signature_correctness_proof(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let different_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values
            let (mut credential_signature, _) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &different_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 9. Issuer signs credential values second time
            let (_, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &different_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 10. Prover processes credential signature
            let res = Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_process_credential_signature_works_for_credential_secrets_blinding_factors_not_correspond_to_signature(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 6. Prover blinds master secret second time
            let (_, credential_secrets_blinding_factors, _) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 8. Issuer creates credential values

            // 9. Issuer signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 10. Prover processes credential signature
            let res = Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_process_credential_signature_works_for_use_different_nonce() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let master_secret = Prover::new_master_secret().unwrap();
            let credential_values = helpers::gvt_credential_values(&master_secret);

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            let other_nonce = new_nonce().unwrap();

            // 9. Prover processes credential signature
            let res = Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &other_nonce,
                None,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }
    }

    mod helpers {
        use super::*;

        pub fn gvt_credential_schema() -> CredentialSchema {
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("name").unwrap();
            credential_schema_builder.add_attr("sex").unwrap();
            credential_schema_builder.add_attr("age").unwrap();
            credential_schema_builder.add_attr("height").unwrap();
            credential_schema_builder.finalize().unwrap()
        }

        pub fn xyz_credential_schema() -> CredentialSchema {
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("status").unwrap();
            credential_schema_builder.add_attr("period").unwrap();
            credential_schema_builder.finalize().unwrap()
        }

        pub fn pqr_credential_schema() -> CredentialSchema {
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("name").unwrap();
            credential_schema_builder.add_attr("address").unwrap();
            credential_schema_builder.finalize().unwrap()
        }

        pub fn non_credential_schema() -> NonCredentialSchema {
            let mut non_credential_schema_builder =
                Issuer::new_non_credential_schema_builder().unwrap();
            non_credential_schema_builder
                .add_attr("master_secret")
                .unwrap();
            non_credential_schema_builder.finalize().unwrap()
        }

        pub fn gvt_credential_values(master_secret: &MasterSecret) -> CredentialValues {
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_value_hidden("master_secret", &master_secret.value().unwrap())
                .unwrap();
            credential_values_builder
                .add_dec_known("name", "1139481716457488690172217916278103335")
                .unwrap();
            credential_values_builder
                .add_dec_known(
                    "sex",
                    "5944657099558967239210949258394887428692050081607692519917050011144233115103",
                )
                .unwrap();
            credential_values_builder
                .add_dec_known("age", "28")
                .unwrap();
            credential_values_builder
                .add_dec_known("height", "175")
                .unwrap();
            credential_values_builder.finalize().unwrap()
        }

        pub fn xyz_credential_values(master_secret: &MasterSecret) -> CredentialValues {
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_value_hidden("master_secret", &master_secret.value().unwrap())
                .unwrap();
            credential_values_builder
                .add_dec_known("status", "51792877103171595686471452153480627530895")
                .unwrap();
            credential_values_builder
                .add_dec_known("period", "8")
                .unwrap();
            credential_values_builder.finalize().unwrap()
        }

        pub fn pqr_credential_values(master_secret: &MasterSecret) -> CredentialValues {
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_value_hidden("master_secret", &master_secret.value().unwrap())
                .unwrap();
            credential_values_builder
                .add_dec_known("name", "1139481716457488690172217916278103335")
                .unwrap();
            credential_values_builder
                .add_dec_known("address", "51792877103171595686471452153480627530891")
                .unwrap();
            credential_values_builder.finalize().unwrap()
        }

        pub fn pqr_credential_values_1(master_secret: &MasterSecret) -> CredentialValues {
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_value_hidden("master_secret", &master_secret.value().unwrap())
                .unwrap();
            credential_values_builder
                .add_dec_known("name", "7181645748869017221791627810333511394")
                .unwrap();
            credential_values_builder
                .add_dec_known("address", "51792877103171595686471452153480627530891")
                .unwrap();
            credential_values_builder.finalize().unwrap()
        }

        pub fn gvt_sub_proof_request() -> SubProofRequest {
            let mut gvt_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            gvt_sub_proof_request_builder
                .add_revealed_attr("name")
                .unwrap();
            gvt_sub_proof_request_builder
                .add_predicate("age", "GE", 18)
                .unwrap();
            gvt_sub_proof_request_builder.finalize().unwrap()
        }

        pub fn xyz_sub_proof_request() -> SubProofRequest {
            let mut xyz_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            xyz_sub_proof_request_builder
                .add_revealed_attr("status")
                .unwrap();
            xyz_sub_proof_request_builder
                .add_predicate("period", "GE", 4)
                .unwrap();
            xyz_sub_proof_request_builder.finalize().unwrap()
        }

        pub fn pqr_sub_proof_request() -> SubProofRequest {
            let mut pqr_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            pqr_sub_proof_request_builder
                .add_revealed_attr("address")
                .unwrap();
            pqr_sub_proof_request_builder.finalize().unwrap()
        }

        pub fn gvt_sub_proof_request_1() -> SubProofRequest {
            let mut gvt_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            gvt_sub_proof_request_builder
                .add_revealed_attr("sex")
                .unwrap();
            gvt_sub_proof_request_builder.finalize().unwrap()
        }
    }
}
