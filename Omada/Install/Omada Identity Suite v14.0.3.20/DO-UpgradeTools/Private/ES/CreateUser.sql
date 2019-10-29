Declare @DisplayName nvarchar(10)
Set @DisplayName = 'SRVC_OMADA'

Declare @ile int
Select @ile=Count(*) from tblUser where UserName=@DisplayName
Declare @Number int
Declare @ID int


if @ile=0
begin
	Declare @newID nvarchar(36)
	Set @newID = NEWID()
	Declare @ParentID int
	Select @ParentID=(ID) from tblDataObject where DisplayName='Users'
	Select @Number=(Max(Number)+1) from tblDataObject where parentId=@ParentID

	Declare @CreatedBy int
	Set @CreatedBy=1054
	Declare @SearchData varchar(256)
	Set @SearchData = '100 omada service dispNameomada dispNameservice jQMAAAomada jwMAAAservice ' + @DisplayName + ' $20160630$'
	Declare @SecurityObject int
	Select @SecurityObject=(ID) from tblDataObject where DisplayName='Users'
	
	Declare @temp as varchar(4000)
	Set @temp = '<Properties>
  <Property Id="909" Modified="true">omada</Property>
  <Property Id="911" Modified="true">service</Property>
  <Property Id="910" Modified="true" />
  <Property Id="902" Modified="true" />
  <Property Id="903" Modified="true" />
  <Property Id="917" Modified="true" />
  <Property Id="905" Modified="true" />
  <Property Id="912" Modified="true" />
  <Property Id="904" Modified="true" />
  <Property Id="907" Modified="true" />
  <Property Id="923" Modified="true" />
  <Property Id="949" Modified="true" />
  <Property Id="1000070" Modified="true" />
</Properties>
'
	Declare @xml XML
	SET @xml = CAST(@temp AS XML);
	Declare @VersionID int
	Declare @PersGroupID int
	Set @PersGroupID = 3503 -- Don't know how to create a new one, using one from Administrators account

	Insert into tblDataObject(UID,Number,DisplayName,CreateTime,CreatedBy,
	ChangeTime,ChangedBy,AbsDuration,Duration,Deleted,
	ParentID,Template,SecurityObjectID,UseClonePermissions,DataObjectTypeID, 
	SearchData)--,TS
	Values(@newID,@Number,@DisplayName,GETDATE(),@CreatedBy,
	GETDATE(),@CreatedBy,0,0,0,
	@ParentID,0,@SecurityObject,0,905,
	@SearchData)--,@TS
	Set @ID = @@IDENTITY

	Insert into tblDataObjectVersion(CreatedBy,CreateTime,CurrentVer,FirstVer,DataObjectID,DataObjectTypeID,PropertyXML)
	Values(@CreatedBy,GETDATE(),1,0,@ID,905,@xml)
	Set @VersionID = @@IDENTITY

	Insert into tblDataObjectVersionPropertyValueText(DataObjectVersionID,PropertyID,[Format],PropValue)
	Values (@VersionID,909,0,@DisplayName)
	Insert into tblDataObjectVersionPropertyValueText(DataObjectVersionID,PropertyID,[Format],PropValue)
	Values (@VersionID,911,0,@DisplayName)

	Update tblDataObject set CurrentVersionID=@VersionID where ID=@ID 

	INSERT INTO tblUser(ID,UserName,[Password],[PswSalt],Inactive,PersGroupID,[System],[Type],Culture,LanguageID,TimeZoneID,WorkWeekID)
	VALUES(@ID,@DisplayName,'','',0,@PersGroupID,0,0,'en-US',1000,105,900)

	INSERT INTO tblUserGroupMember(UserGroupID,UserID)
	VALUES(1050,@id)
	--INSERT INTO tblUserGroupMember(UserGroupID,UserID)
	--VALUES(1000025,@id)
	INSERT INTO tblUserGroupMember(UserGroupID,UserID)
	VALUES(@PersGroupID,@id)

end
Else
begin
	Select @id=(ID) from tblDataObject where DisplayName=@DisplayName
end

--add srvc user into data administrators group
Declare @GroupID int
Declare @i int
Declare @NewUID int
Select @NewUID=(ID) from tblDataObject where DisplayName='SRVC_Omada'
Select @GroupID=(ID) from tblDataObject where DisplayName='Data administrators'
Select @i=count(*) from tblUserGroupMember where UserID=@NewUID and UserGroupID=@GroupID

if @i = 0 and @GroupID is not null
begin
	INSERT INTO tblUserGroupMember(UserGroupID,UserID)
	VALUES(@GroupID,@NewUID)
end